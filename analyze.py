import argparse
import csv
import os
import org


OBJECTS = ["Vendor__c", "Invoice__c", "Payment__c"]
SYSTEM_PERMS = ["ModifyAllData", "ViewAllData", "ManageUsers", "AuthorApex", "CustomizeApplication",
                "AssignPermissionSets", "ExportReport"]
ACTIONS = ["Read", "Create", "Edit", "Delete"]


def fetch_users():
    return org.query("SELECT Id, Alias, IsActive, Profile.Name, UserRole.DeveloperName FROM User "
                     "WHERE UserType = 'Standard' ORDER BY Alias")


def fetch_assignments():
    return org.query("SELECT AssigneeId, PermissionSetId, PermissionSet.Name, PermissionSet.IsOwnedByProfile, "
                     "PermissionSet.Profile.Name, PermissionSetGroup.DeveloperName "
                     "FROM PermissionSetAssignment WHERE Assignee.UserType = 'Standard'")


# where a user's access comes from: their profile, a permission set or a permission set group
def source(a):
    if a["PermissionSetGroup"]:
        return a["PermissionSetGroup"]["DeveloperName"]
    if a["PermissionSet"]["IsOwnedByProfile"]:
        return "profile: " + a["PermissionSet"]["Profile"]["Name"]
    return a["PermissionSet"]["Name"]


# what each permission set grants, as short tokens like Vendor__c:create or perm:ViewAllData.
# profiles count too, every profile has a permission set behind it
def fetch_grants():
    grants = {}

    def add(ps_id, token):
        grants.setdefault(ps_id, set()).add(token)

    objects = ", ".join(f"'{o}'" for o in OBJECTS)
    for r in org.query("SELECT Id, " + ", ".join("Permissions" + p for p in SYSTEM_PERMS) + " FROM PermissionSet"):
        for p in SYSTEM_PERMS:
            if r["Permissions" + p]:
                add(r["Id"], "perm:" + p)
    for r in org.query("SELECT ParentId, SobjectType, PermissionsRead, PermissionsCreate, PermissionsEdit, "
                       f"PermissionsDelete FROM ObjectPermissions WHERE SobjectType IN ({objects})"):
        for action in ACTIONS:
            if r["Permissions" + action]:
                add(r["ParentId"], f"{r['SobjectType']}:{action.lower()}")
    for r in org.query("SELECT ParentId, Field FROM FieldPermissions "
                       f"WHERE PermissionsEdit = true AND SobjectType IN ({objects})"):
        add(r["ParentId"], r["Field"] + ":edit")
    names = {r["Id"]: r["DeveloperName"] for r in org.query("SELECT Id, DeveloperName FROM CustomPermission")}
    for r in org.query("SELECT ParentId, SetupEntityId FROM SetupEntityAccess WHERE SetupEntityType = 'CustomPermission'"):
        add(r["ParentId"], "custom:" + names.get(r["SetupEntityId"], r["SetupEntityId"]))
    return grants


# a user's access is everything from their profile, permission sets and groups added together
def effective(user_id, assignments, grants):
    perms = {}
    for a in assignments:
        if a["AssigneeId"] == user_id:
            for token in grants.get(a["PermissionSetId"], ()):
                perms.setdefault(token, set()).add(source(a))
    return perms


def load_policy(path):
    with open(path, newline="") as f:
        return {r["role"]: r["allowed_permission_sets"].split("|") for r in csv.DictReader(f)}


def fetch_set_ids():
    return {r["Name"]: r["Id"] for r in org.query("SELECT Id, Name FROM PermissionSet WHERE IsOwnedByProfile = false")}


# what each role is meant to have, from the permission sets the policy allows it
def role_access(policy, set_ids, grants):
    return {role: set().union(*(grants.get(set_ids.get(name), set()) for name in names))
            for role, names in policy.items()}


def write_csv(path, header, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def write_matrices(out, users, user_perms, roles, columns):
    write_csv(os.path.join(out, "user_matrix.csv"), ["user", "role", "profile", "active"] + columns,
              [[u["Alias"], role_of(u), u["Profile"]["Name"], "yes" if u["IsActive"] else "no"]
               + ["x" if c in user_perms[u["Id"]] else "" for c in columns] for u in users])
    write_csv(os.path.join(out, "role_matrix.csv"), ["role"] + columns,
              [[role] + ["x" if c in perms else "" for c in columns] for role, perms in roles.items()])


def role_of(u):
    return u["UserRole"]["DeveloperName"] if u["UserRole"] else ""


def main():
    parser = argparse.ArgumentParser(description="check who can do what in the salesforce org")
    parser.add_argument("--policy", default="rules/role_policy.csv")
    parser.add_argument("--out", default="output", help="folder for the csv results")
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)

    users = fetch_users()
    assignments = fetch_assignments()
    grants = fetch_grants()
    user_perms = {u["Id"]: effective(u["Id"], assignments, grants) for u in users}
    roles = role_access(load_policy(args.policy), fetch_set_ids(), grants)

    columns = sorted(set().union(*user_perms.values()))
    write_matrices(args.out, users, user_perms, roles, columns)
    print(f"{len(users)} users, {len(columns)} permissions, matrices written to {args.out}")


if __name__ == "__main__":
    main()
