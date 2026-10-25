import argparse
import csv
import org


# carries out reports/remediation-plan.csv. without --apply it only prints what it would do
def main():
    parser = argparse.ArgumentParser(description="remove conflicting access from the remediation plan")
    parser.add_argument("--plan", default="reports/remediation-plan.csv")
    parser.add_argument("--apply", action="store_true", help="actually make the changes")
    args = parser.parse_args()

    with open(args.plan, newline="") as f:
        plan = list(csv.DictReader(f))

    for step in plan:
        user = org.query(f"SELECT Id FROM User WHERE Alias = '{step['user']}'")
        if not user:
            print(f"{step['user']}: no such user, skipping")
            continue
        user_id = user[0]["Id"]

        if step["action"] == "remove":
            found = org.query("SELECT Id FROM PermissionSetAssignment "
                              f"WHERE AssigneeId = '{user_id}' AND PermissionSet.Name = '{step['permission_set']}'")
            if not found:
                print(f"{step['user']}: {step['permission_set']} already removed")
                continue
            print(f"{step['user']}: remove {step['permission_set']} ({step['reason']})")
            if args.apply:
                org.delete("PermissionSetAssignment", found[0]["Id"])
        elif step["action"] == "freeze":
            login = org.query(f"SELECT Id, IsFrozen FROM UserLogin WHERE UserId = '{user_id}'")
            if login and login[0]["IsFrozen"]:
                print(f"{step['user']}: already frozen")
                continue
            print(f"{step['user']}: freeze ({step['reason']})")
            if args.apply:
                org.update("UserLogin", login[0]["Id"], {"IsFrozen": True})
        else:
            print(f"{step['user']}: accepted, no change")

    if not args.apply:
        print("dry run, nothing changed. run again with --apply")


if __name__ == "__main__":
    main()
