from analyze import conflicts, effective, load_rules, other_findings, role_access, status


def assignment(user, ps_id, name, profile=None):
    return {"AssigneeId": user, "PermissionSetId": ps_id, "PermissionSetGroup": None,
            "PermissionSet": {"Name": name, "IsOwnedByProfile": profile is not None,
                              "Profile": {"Name": profile} if profile else None}}


rules = load_rules("rules/sod_rules.csv")
grants = {
    "p1": {"perm:ExportReport"},
    "vm": {"Vendor__c:create", "Vendor__c:edit", "Vendor__c.Bank_Account__c:edit"},
    "pa": {"custom:Approve_Payments", "Payment__c:edit"},
    "ua": {"perm:AssignPermissionSets"},
}
assignments = [
    assignment("u1", "p1", "ignored", profile="Standard User"),
    assignment("u1", "vm", "AP_Vendor_Maintenance"),
    assignment("u1", "pa", "AP_Payment_Approval"),
    assignment("u2", "pa", "AP_Payment_Approval"),
    assignment("u3", "ua", "User_Admin"),
    assignment("u3", "pa", "AP_Payment_Approval"),
]

# access from the profile and permission sets is added up, and we keep where it came from
u1 = effective("u1", assignments, grants)
assert u1["perm:ExportReport"] == {"profile: Standard User"}
assert u1["Vendor__c:create"] == {"AP_Vendor_Maintenance"}
assert effective("nobody", assignments, grants) == {}

# vendor maintenance + payment approval breaks SOD-01 and SOD-02
found = {rule["id"] for rule, a, b in conflicts(u1, rules)}
assert found == {"SOD-01", "SOD-02"}

# approving on its own is fine
assert conflicts(effective("u2", assignments, grants), rules) == []

# either side token is enough: assign permission sets counts the same as manage users
assert [rule["id"] for rule, a, b in conflicts(effective("u3", assignments, grants), rules)] == ["SOD-05"]

# what a role is meant to have comes only from its allowed permission sets
roles = role_access({"AP_Manager": ["AP_Payment_Approval"], "Typo": ["Not_A_Set"]},
                    {"AP_Payment_Approval": "pa"}, grants)
assert roles["AP_Manager"] == grants["pa"]
assert roles["Typo"] == set()

policy = {"AP_Clerk": ["AP_Invoice_Entry"]}
clerk = {"IsActive": True, "UserRole": {"DeveloperName": "AP_Clerk"}}
leaver = {"IsActive": False, "UserRole": {"DeveloperName": "AP_Clerk"}}
no_role = {"IsActive": True, "UserRole": None}

assert other_findings(clerk, {}, ["AP_Invoice_Entry"], policy) == []
assert [k for k, d in other_findings(clerk, {}, ["AP_Invoice_Entry", "View_All_Data"], policy)] == \
    ["access outside the role policy"]
assert "inactive user still has access" in [k for k, d in other_findings(leaver, {}, ["AP_Invoice_Entry"], policy)]
assert [k for k, d in other_findings(no_role, {}, ["GenieAdmin"], policy)] == ["not covered by the role policy"]
assert [k for k, d in other_findings(no_role, {"perm:ModifyAllData": {"profile: System Administrator"}}, [], policy)] == \
    ["privileged access"]

# frozen only matters for an active user, inactive wins
assert status(clerk) == "yes"
assert status({"IsActive": True, "frozen": True}) == "frozen"
assert status({"IsActive": False, "frozen": True}) == "no"

print("all tests passed")
