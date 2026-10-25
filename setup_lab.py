import org


DOMAIN = "ag-lab-demo.example.com"

# test users for the lab. some of them have access they shouldn't have, on purpose,
# so the analyzer has something real to find. Casey left the company and was
# deactivated, but nobody removed their permission sets.
# first, last, alias, role, profile, permission sets, active
USERS = [
    ("Alex", "Chen", "achen", "AP_Clerk", "Standard Platform User", ["AP_Invoice_Entry", "AP_Vendor_Maintenance"], True),
    ("Jordan", "Patel", "jpatel", "AP_Manager", "Standard Platform User", ["AP_Payment_Approval", "AP_Vendor_Maintenance"], True),
    ("Sam", "Rivera", "srivera", "Vendor_Data", "Standard Platform User", ["AP_Vendor_Maintenance"], True),
    ("Casey", "Nguyen", "cnguyen", "AP_Clerk", "Standard Platform User", ["AP_Invoice_Entry", "AP_Payment_Approval"], False),
    ("Taylor", "Brooks", "tbrooks", "IT_Support", "Standard User", ["User_Admin", "AP_Payment_Approval"], True),
    ("Morgan", "Lee", "mlee", "Sales_Analyst", "Standard User", ["Report_Export", "View_All_Data"], True),
]


def ids(soql, key):
    return {r[key]: r["Id"] for r in org.query(soql)}


def main():
    profiles = ids("SELECT Id, Name FROM Profile WHERE Name IN ('Standard User', 'Standard Platform User')", "Name")
    roles = ids("SELECT Id, DeveloperName FROM UserRole", "DeveloperName")
    sets = ids("SELECT Id, Name FROM PermissionSet WHERE IsOwnedByProfile = false", "Name")

    for first, last, alias, role, profile, perm_sets, active in USERS:
        username = f"{first}.{last}@{DOMAIN}".lower()
        found = org.query(f"SELECT Id, IsActive FROM User WHERE Username = '{username}'")
        if found:
            user_id = found[0]["Id"]
            print(alias, "already exists")
        else:
            user_id = org.create("User", {
                "FirstName": first, "LastName": last, "Alias": alias, "Username": username, "Email": username,
                "ProfileId": profiles[profile], "UserRoleId": roles[role],
                "TimeZoneSidKey": "America/Toronto", "LocaleSidKey": "en_CA",
                "EmailEncodingKey": "UTF-8", "LanguageLocaleKey": "en_US",
                # the dev org only has a few content licenses, and the test users don't need content
                "UserPermissionsSFContentUser": False,
            })
            print(alias, "created")

        assigned = {r["PermissionSet"]["Name"] for r in org.query(
            f"SELECT PermissionSet.Name FROM PermissionSetAssignment WHERE AssigneeId = '{user_id}'")}
        for name in perm_sets:
            if name not in assigned:
                org.create("PermissionSetAssignment", {"AssigneeId": user_id, "PermissionSetId": sets[name]})
                print("  assigned", name)

        # assignments have to go in before deactivating, salesforce won't add them to an inactive user
        if not active and (not found or found[0]["IsActive"]):
            org.update("User", user_id, {"IsActive": False})
            print("  deactivated")


if __name__ == "__main__":
    main()
