"""aws-sso-apply

Expected shape of the `conf` argument:
{
    'master-aws-account': '<123412341234>',  # the AWS account number that contains your AWS SSO configuration
    'aws-sso-arn': 'arn:aws:sso:::instance/ssoins-<123abc123abc123abc>',  # the ARN of the AWS SSO instance to manage
    'accounts': {
         'myacc1': {
             'account': '<789078907890>',  # accno of another account
             'roles': ['admin', 'read-only'],  # roles in that account that trust the master account
         },
         'myacc2': {
             'account': '<567856785678>',
             'roles': ['admin', 'read-only', 'billing'],
         },
    },
    'roles': {
        'ReadOnly': {
            'policies': ['arn:aws:iam::aws:policy/ReadOnlyAccess'],  # policies to attach to the permission set
            'profiles': [{
                'account': 'myacc1',
                'role': 'read-only',
            }, {
                'account': 'myacc2',
                'role': 'read-only',
            }],
        },
        'Billing': {
            'profiles': [{
                'account': 'myacc2',
                'role': 'billing',
            }],
        },
    },
    'users': {
        'jane.doe@company.com': ['Billing'],
        'john.doe@company.com': ['ReadOnly'],
        'richard.roe@company.com': ['Billing', 'ReadOnly'],
    },
}
"""

import boto3
import difflib
import json


def make_statement(conf, role_name):
    arns = []
    role = conf["roles"][role_name]

    if "profiles" in role:
        for profile in role["profiles"]:
            account = profile["account"]
            dest_role = profile["role"]
            account_id = conf["accounts"][account]["account"]
            arns.append("arn:aws:iam::{}:role/{}".format(account_id, dest_role))

    if arns:
        return dict(
            Sid=role_name,
            Action=["sts:AssumeRole"],
            Resource=sorted(arns),
            Effect="Allow",
        )


def get_policy_for_user(conf, username):
    statements = []
    managed = []

    for rolename in conf["users"][username]:
        statement = make_statement(conf, rolename)
        if statement:
            statements.append(statement)

        managed_policies = conf["roles"][rolename].get("policies") or []
        managed.extend(managed_policies)

    if statements:
        content = json.dumps(
            dict(Statement=sorted(statements, key=lambda item: item["Sid"])),
            indent=2,
            sort_keys=True,
        )
    else:
        content = ""

    return {
        "inline": content,
        "managed": sorted(set(managed)),
    }


def normalise_json(string_data):
    try:
        loaded = json.loads(string_data)
    except:
        return "!unknown"
    return json.dumps(loaded, indent=2)


class OutputHandler:
    def __call__(self, message):
        raise NotImplementedError

    def done(self):
        pass


class CollectOutputHandler(OutputHandler):
    def __init__(self):
        self.output = []

    def __call__(self, message):
        self.output.append(message)

    def done(self):
        return self.output


class PrintOutputHandler:
    def __call__(self, message):
        print(json.dumps(message), indent=2)


class CallableOutputHandler:
    def __init__(self, supplied_callable):
        self.supplied_callable = supplied_callable

    def __call__(self, message):
        supplied_callable(message)


def output_handler_factory(output_handler=None):
    if not output_handler:
        return CollectOutputHandler()
    elif output_handler == "print":
        return PrintOutputHandler()
    elif isinstance(output_handler, callable):
        return CallableOutputHandler(output_handler)
    raise Exception("Unknown output_handler")


def sso_apply(
    conf,
    *,
    check_local_only=False,
    specific_username=None,
    apply_changes=False,
    retain_full_user_email=False,
    output_handler=None,
):
    if check_local_only:
        for username in conf["users"]:
            get_policy_for_user(conf, username)
        return

    output_handler = output_handler_factory(output_handler)

    sso_admin = boto3.client("sso-admin")

    instances = sso_admin.list_instances()
    matching_instances = [
        instance
        for instance in instances["Instances"]
        if instance["InstanceArn"] == conf["aws-sso-arn"]
    ]

    if len(matching_instances) != 1:
        raise ValueError(
            "Expected to find one SSO instance, found {}".format(
                len(matching_instances)
            )
        )

    instance = matching_instances[0]
    instance_arn = instance["InstanceArn"]
    instance_id = instance["IdentityStoreId"]

    sso_identity = boto3.client("identitystore")

    users = {}
    for user_email in conf["users"]:
        user_identifier = user_email.split("@")[0]
        found_users = sso_identity.list_users(
            IdentityStoreId=instance_id,
            MaxResults=25,
            Filters=[
                {
                    "AttributePath": "UserName",
                    "AttributeValue": user_identifier,
                }
            ],
        )["Users"]

        if found_users:
            users[user_email] = found_users[0]

    permission_set_arns = []
    list_permission_sets_params = dict(
        InstanceArn=instance_arn,
    )
    while True:
        response = sso_admin.list_permission_sets(**list_permission_sets_params)
        permission_set_arns.extend(response["PermissionSets"])
        next_token = response.get("NextToken")
        if next_token:
            list_permission_sets_params["NextToken"] = next_token
        else:
            break

    permission_sets_by_name = {}
    for permission_set_arn in permission_set_arns:
        permission_set = sso_admin.describe_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn,
        )["PermissionSet"]

        name = permission_set["Name"]

        if name in permission_sets_by_name:
            raise ValueError(f"Duplicate permission set name {name}")

        account_assignments = sso_admin.list_account_assignments(
            InstanceArn=instance_arn,
            AccountId=conf["master-aws-account"],
            PermissionSetArn=permission_set_arn,
        )["AccountAssignments"]

        inline_policy = sso_admin.get_inline_policy_for_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn,
        )["InlinePolicy"]

        managed_policies = sso_admin.list_managed_policies_in_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn,
        )["AttachedManagedPolicies"]

        permission_sets_by_name[name] = {
            "arn": permission_set_arn,
            "object": permission_set,
            "inline_policy": inline_policy,
            "managed_policies": managed_policies,
            "account_assignments": account_assignments,
        }

    changes_by_user = {}

    for username in conf["users"]:
        if specific_username and specific_username != username:
            continue

        user_shortname = username.split("@")[0]
        user_id = (users.get(username) or {}).get("UserId")

        existing_permission_set = permission_sets_by_name.get(user_shortname) or None

        required_policies = get_policy_for_user(conf, username)

        changes = {}

        if not existing_permission_set:
            changes["permission_set"] = {
                "action": "create",
                "name": user_shortname,
                "session_duration": "PT12H",
                "user_id": user_id,
            }
            if required_policies["inline"]:
                changes["inline_policy"] = {
                    "action": "set",
                    "policy": required_policies["inline"],
                }
            if required_policies["managed"]:
                changes["managed_policies"] = {
                    "action": "set",
                    "attach_policy_arns": set(required_policies["managed"]),
                    "detach_policy_arns": set(),
                }
        else:
            permission_set_arn = existing_permission_set["object"]["PermissionSetArn"]
            required_inline_policy = required_policies["inline"]
            current_inline_policy = existing_permission_set["inline_policy"]

            if required_inline_policy != current_inline_policy:

                if not required_policies["inline"]:
                    changes["inline_policy"] = {
                        "action": "delete",
                        "permission_set_arn": permission_set_arn,
                        "_old": current_inline_policy,
                    }
                else:
                    changes["inline_policy"] = {
                        "action": "set",
                        "policy": required_inline_policy,
                        "permission_set_arn": permission_set_arn,
                        "_old": current_inline_policy,
                    }

            required_managed_policy_arns = set(required_policies["managed"])
            current_managed_policy_arns = set(
                p["Arn"] for p in existing_permission_set["managed_policies"]
            )

            managed_policies_to_attach = (
                required_managed_policy_arns - current_managed_policy_arns
            )
            managed_policies_to_detach = (
                current_managed_policy_arns - required_managed_policy_arns
            )
            if managed_policies_to_attach or managed_policies_to_detach:
                changes["managed_policies"] = {
                    "action": "set",
                    "permission_set_arn": permission_set_arn,
                    "attach_policy_arns": managed_policies_to_attach,
                    "detach_policy_arns": managed_policies_to_detach,
                }

            if not existing_permission_set["account_assignments"]:
                changes["account_assignment"] = {
                    "action": "assign",
                    "permission_set_arn": permission_set_arn,
                    "user_id": user_id,
                }

        changes_by_user[username] = changes

    for username, changes in changes_by_user.items():
        if not changes:
            output_handler(
                {
                    "message": f"No changes for {username}",
                    "username": username,
                }
            )
            continue

        output_changes = []

        for change_name, change_options in changes.items():
            change_nice_name = change_name.replace("_", " ").title()
            changes_to_print = dict(change_options)
            if change_name == "inline_policy":
                src = (
                    changes_to_print.pop("_old") if "_old" in changes_to_print else "{}"
                )
                dest = (
                    changes_to_print["policy"]
                    if changes_to_print["action"] == "set"
                    else "{}"
                )
                changes_to_print.pop("policy", None)

                differ = difflib.Differ()
                changes_to_print["policy (diff lines)"] = [
                    diffline
                    for diffline in differ.compare(
                        normalise_json(src).splitlines(),
                        normalise_json(dest).splitlines(),
                    )
                    if not diffline.startswith("  ")
                ]

            change_items = []

            for key, value in changes_to_print.items():
                change_items.append(
                    {
                        "key": key,
                        "value": value,
                    }
                )

            output_changes.append(
                {
                    "name": change_nice_name,
                    "change": {
                        "old": src,
                        "new": dest,
                    },
                    "details": change_items,
                }
            )

        output_handler(
            {
                "message": f"Changes for {username}",
                "username": username,
                "changes": output_changes,
            }
        )

        if apply_changes:
            created_permission_set_arn = None
            permission_set_arns_to_assign = []
            permission_set_arns_to_provision = set()
            user_id = None

            if "permission_set" in changes:
                permission_set_change = changes["permission_set"]
                if permission_set_change["action"] == "create":
                    created_permission_set = sso_admin.create_permission_set(
                        Name=permission_set_change["name"],
                        InstanceArn=instance_arn,
                        SessionDuration=permission_set_change["session_duration"],
                    )

                    created_permission_set_arn = created_permission_set[
                        "PermissionSet"
                    ]["PermissionSetArn"]
                    permission_set_arns_to_assign.append(
                        {
                            "permission_set_arn": created_permission_set_arn,
                            "user_id": permission_set_change["user_id"],
                        }
                    )
                else:
                    raise ValueError(
                        "Unknown action for permission set change {}".format(
                            permission_set_change["action"]
                        )
                    )

            if "inline_policy" in changes:
                inline_policy_change = changes["inline_policy"]
                if inline_policy_change["action"] == "delete":
                    sso_admin.put_inline_policy_to_permission_set(
                        InstanceArn=instance_arn,
                        PermissionSetArn=inline_policy_change["permission_set_arn"],
                    )
                    permission_set_arns_to_provision.add(
                        inline_policy_change["permission_set_arn"]
                    )
                elif inline_policy_change["action"] == "set":
                    permission_set_arn = (
                        created_permission_set_arn
                        or inline_policy_change["permission_set_arn"]
                    )
                    sso_admin.put_inline_policy_to_permission_set(
                        InstanceArn=instance_arn,
                        PermissionSetArn=permission_set_arn,
                        InlinePolicy=inline_policy_change["policy"],
                    )
                    permission_set_arns_to_provision.add(permission_set_arn)
                else:
                    raise ValueError(
                        "Unknown action for inline policy change {}".format(
                            inline_policy_change["action"]
                        )
                    )

            if "managed_policies" in changes:
                managed_policies_change = changes["managed_policies"]
                if managed_policies_change["action"] == "set":
                    to_attach = managed_policies_change.get("attach_policy_arns")
                    to_detach = managed_policies_change.get("detach_policy_arns")

                    if to_attach:
                        permission_set_arn = (
                            created_permission_set_arn
                            or managed_policies_change["permission_set_arn"]
                        )
                        for to_attach_arn in to_attach:
                            sso_admin.attach_managed_policy_to_permission_set(
                                InstanceArn=instance_arn,
                                PermissionSetArn=permission_set_arn,
                                ManagedPolicyArn=to_attach_arn,
                            )
                        permission_set_arns_to_provision.add(permission_set_arn)
                    if to_detach:
                        for to_detach_arn in to_detach:
                            sso_admin.detach_managed_policy_from_permission_set(
                                InstanceArn=instance_arn,
                                PermissionSetArn=managed_policies_change[
                                    "permission_set_arn"
                                ],
                                ManagedPolicyArn=to_detach_arn,
                            )
                        permission_set_arns_to_provision.add(
                            managed_policies_change["permission_set_arn"]
                        )
                else:
                    raise ValueError(
                        "Unknown action for managed policies change {}".format(
                            managed_policies_change["action"]
                        )
                    )

            if "account_assignment" in changes:
                account_assignment_change = changes["account_assignment"]
                permission_set_arns_to_assign.append(
                    {
                        "permission_set_arn": account_assignment_change[
                            "permission_set_arn"
                        ],
                        "user_id": account_assignment_change["user_id"],
                    }
                )

            already_assigned = set()
            for arn_and_id in permission_set_arns_to_assign:
                permission_set_arn = arn_and_id["permission_set_arn"]
                user_id = arn_and_id["user_id"]
                as_tuple = (permission_set_arn, user_id)
                if as_tuple in already_assigned:
                    continue
                already_assigned.add(as_tuple)
                if user_id:
                    sso_admin.create_account_assignment(
                        InstanceArn=instance_arn,
                        TargetId=conf["master-aws-account"],
                        TargetType="AWS_ACCOUNT",
                        PermissionSetArn=permission_set_arn,
                        PrincipalType="USER",
                        PrincipalId=user_id,
                    )
                else:
                    output_handler(
                        {
                            "message": "User does not exist, unable to assign",
                            "username": username,
                        }
                    )

            for permission_set_arn in permission_set_arns_to_provision:
                sso_admin.provision_permission_set(
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set_arn,
                    TargetId=conf["master-aws-account"],
                    TargetType="AWS_ACCOUNT",
                )
            output_handler(
                {
                    "message": "Changes applied",
                }
            )

    if apply_changes:
        output_handler(
            {
                "message": "All changes applied",
            }
        )

    return output_handler.done()
