import org


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


def main():
    users = fetch_users()
    assignments = fetch_assignments()
    for u in users:
        mine = [source(a) for a in assignments if a["AssigneeId"] == u["Id"]]
        print(u["Alias"], "active" if u["IsActive"] else "inactive", mine)


if __name__ == "__main__":
    main()
