import argparse
import csv
import os
import org


OBJECTS = ["Vendor__c", "Invoice__c", "Payment__c"]
SYSTEM_PERMS = ["ModifyAllData", "ViewAllData", "ManageUsers", "AuthorApex", "CustomizeApplication",
                "AssignPermissionSets", "ExportReport"]
ACTIONS = ["Read", "Create", "Edit", "Delete"]
PRIVILEGED = ["perm:ModifyAllData", "perm:ViewAllData", "perm:ManageUsers", "perm:AuthorApex",
              "perm:CustomizeApplication"]
RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def fetch_users():
    return org.query("SELECT Id, Alias, IsActive, Profile.Name, UserRole.DeveloperName FROM User "
                     "WHERE UserType = 'Standard' ORDER BY Alias")


def fetch_frozen():
    return {r["UserId"] for r in org.query("SELECT UserId FROM UserLogin WHERE IsFrozen = true")}


# a frozen user is still active in salesforce but can't log in
def status(u):
    if not u["IsActive"]:
        return "no"
    return "frozen" if u.get("frozen") else "yes"


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


def load_rules(path):
    with open(path, newline="") as f:
        rules = list(csv.DictReader(f))
    for r in rules:
        r["side_a"] = r["side_a"].split("|")
        r["side_b"] = r["side_b"].split("|")
    return rules


# a rule is broken when someone has at least one permission from each side
def conflicts(perms, rules):
    found = []
    for rule in rules:
        a = [t for t in rule["side_a"] if t in perms]
        b = [t for t in rule["side_b"] if t in perms]
        if a and b:
            found.append((rule, a, b))
    return found


def explain(tokens, perms):
    return "; ".join(f"{t} from {', '.join(sorted(perms[t]))}" for t in tokens)


# things that aren't SoD conflicts but still need a look in an access review
def other_findings(user, perms, assigned, policy):
    found = []
    admin = [t for t in PRIVILEGED if t in perms]
    if admin:
        found.append(("privileged access", explain(admin, perms)))
    if not user["IsActive"] and assigned:
        found.append(("inactive user still has access", ", ".join(assigned)))
    role = role_of(user)
    if role in policy:
        extra = [name for name in assigned if name not in policy[role]]
        if extra:
            found.append(("access outside the role policy", f"{role} doesn't allow " + ", ".join(extra)))
    elif assigned:
        found.append(("not covered by the role policy", "no role in the policy, has " + ", ".join(assigned)))
    return found


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
              [[u["Alias"], role_of(u), u["Profile"]["Name"], status(u)]
               + ["x" if c in user_perms[u["Id"]] else "" for c in columns] for u in users])
    write_csv(os.path.join(out, "role_matrix.csv"), ["role"] + columns,
              [[role] + ["x" if c in perms else "" for c in columns] for role, perms in roles.items()])


def role_of(u):
    return u["UserRole"]["DeveloperName"] if u["UserRole"] else ""


def main():
    parser = argparse.ArgumentParser(description="check who can do what in the salesforce org")
    parser.add_argument("--rules", default="rules/sod_rules.csv")
    parser.add_argument("--policy", default="rules/role_policy.csv")
    parser.add_argument("--out", default="output", help="folder for the csv results")
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)

    users = fetch_users()
    frozen = fetch_frozen()
    for u in users:
        u["frozen"] = u["Id"] in frozen
    assignments = fetch_assignments()
    grants = fetch_grants()
    user_perms = {u["Id"]: effective(u["Id"], assignments, grants) for u in users}
    policy = load_policy(args.policy)
    roles = role_access(policy, fetch_set_ids(), grants)

    columns = sorted(set().union(*user_perms.values()))
    write_matrices(args.out, users, user_perms, roles, columns)
    print(f"{len(users)} users, {len(columns)} permissions, matrices written to {args.out}")

    rules = load_rules(args.rules)
    for role, perms in roles.items():
        for rule, a, b in conflicts(perms, rules):
            print(f"role design problem: {role} breaks {rule['id']} by itself")

    rows = []
    for u in users:
        perms = user_perms[u["Id"]]
        for rule, a, b in conflicts(perms, rules):
            rows.append([u["Alias"], status(u), rule["id"], rule["risk"], rule["name"],
                         explain(a, perms), explain(b, perms)])
    rows.sort(key=lambda r: (RISK_ORDER.get(r[3], 9), r[2], r[0]))
    write_csv(os.path.join(args.out, "sod_conflicts.csv"),
              ["user", "active", "rule", "risk", "conflict", "side_a", "side_b"], rows)
    print()
    print(f"{len(rows)} SoD conflicts across {len({r[0] for r in rows})} users")
    for r in rows:
        print(f"  {r[3]:<8} {r[2]}  {r[0]:<8} {r[4]}")

    findings = []
    for u in users:
        assigned = sorted({source(a) for a in assignments
                           if a["AssigneeId"] == u["Id"] and not source(a).startswith("profile: ")})
        for kind, detail in other_findings(u, user_perms[u["Id"]], assigned, policy):
            findings.append([u["Alias"], status(u), kind, detail])
    write_csv(os.path.join(args.out, "access_findings.csv"), ["user", "active", "finding", "detail"], findings)
    print()
    print(f"{len(findings)} other access findings")
    for f in findings:
        print(f"  {f[0]:<8} {f[2]}")


if __name__ == "__main__":
    main()
