# access-governance-lab

Checking who can do what in a Salesforce org. This is a segregation of duties (SoD) conflict check and a role-to-permission matrix, built on a free Salesforce Developer Edition org with a small accounts payable setup.

Still working on it.

## The lab org
force-app has the Salesforce metadata:
- Three custom objects for accounts payable: Vendor__c (with a bank account field), Invoice__c and Payment__c (with an Approved__c checkbox). Field history is on for the bank account and for Approved__c.
- An Approve_Payments custom permission and a validation rule on Payment__c, so only someone with that permission can approve a payment. I tested it with my admin account and it got blocked, which is what I wanted. Being an admin isn't the same as being an approver.
- Six permission sets: AP_Vendor_Maintenance, AP_Invoice_Entry, AP_Payment_Approval, Report_Export, View_All_Data and User_Admin. The last two wouldn't deploy at first, because View All Data and Manage Users need other permissions turned on with them.
- Five roles: AP_Clerk, AP_Manager, Vendor_Data, IT_Support and Sales_Analyst.
- Field access for the admin profile. Deploying the fields doesn't give anyone access to them, so my first query failed with "No such column" until I added this.

setup_lab.py creates six test users with a role and permission sets each. Some of them get access they shouldn't have on purpose, so the analyzer has something to find. One of them (cnguyen) left the company and was deactivated, but nobody removed their permission sets.

```
sf org login web --alias aglab
sf project deploy start --source-dir force-app --target-org aglab
python setup_lab.py
```

All the Python goes through the sf CLI (org.py), so the code never sees a password or token. It uses the aglab alias unless SF_TARGET_ORG says otherwise. The usernames use a made up domain and the results only show user aliases.

## Rules
rules/sod_rules.csv has six SoD rules. Each rule has two sides, and a user breaks it if they have at least one permission from each side. Permissions are written as short tokens:
- Vendor__c:create for object access
- Vendor__c.Bank_Account__c:edit for field access
- perm:ViewAllData for system permissions
- custom:Approve_Payments for custom permissions

For example SOD-02 is Vendor__c.Bank_Account__c:edit against custom:Approve_Payments. It's Critical because that person could change a vendor's bank account to their own and then approve the payment.

rules/role_policy.csv lists which permission sets each role is allowed to have.

## How the analyzer works
```
python analyze.py --out reports/first-run
```

- It pulls every permission set assignment. In Salesforce every profile has a permission set behind it, so this gets profile access too. Permission set groups work the same way.
- It reads what each permission set grants (system, object, field and custom permissions) and adds it all up for each user, keeping track of where each permission came from. So a conflict says "custom:Approve_Payments from AP_Payment_Approval" and you know which assignment to remove.
- It writes user_matrix.csv (every user against every permission) and role_matrix.csv (what each role gets from the permission sets the policy allows).
- It checks every user against the SoD rules. It checks every role too, so a role that breaks a rule by design would show up.
- It also flags privileged system permissions, inactive users who still have permission sets, access outside the role policy and users that have no role in the policy.
- Frozen users show as frozen in the active column.

The tests don't need an org:

```
python test_analyze.py
```

output/ is the default results folder and it's in .gitignore, so only the runs in reports get pushed.
