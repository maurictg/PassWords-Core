# PassWords-Core
A brand new core

# Create easy a password manager

## Step 1: Create database file
```csharp
using PassWordsCore;
//Your code logic

//Initialize db
Database.EnsureCreated();

//Create PassWords database
Database.CreateDB("YourDBName","YourPassword");
```

## Step 2: Login into database
```csharp
static Database db = new Database();
db.Login("YourDBName","YourPassword");
```

## Step 3: Create account
```csharp
//Create account object
var account = new Account()
{
  Username = "Test",
  Password = "Test123",
  Title = "MyAccount",
  Description = "Test the account",
  Type = "Email"
};
//Add account to current database
db.Add(account);
```

## Step 4: Get accounts
```csharp
List<Account> accounts = db.GetAccounts();
```

## Step 5: Edit account
```csharp
var testaccount = accounts.FirstOrDefault(a => a.Title == "MyAccount");
testaccount.Title = "HelloWorld";
db.Update(testacccount);
```

## Step 6: Delete account
```csharp
var testaccount = accounts.First(a => a.Title == "MyAccount");
db.Delete(testacccount);
```

## Step 7: Change database password
```csharp
db.UpdatePassword("oldpass","newpass");
```

## Step 8: Backup database
```csharp
db.Backup("destinationpath/database.db");
```

## Step 9: Delete database
```csharp
Database.DeleteDB("YourDBName");
```

## Step 10: List databases
```csharp
List<DB> alldatabases = Database.ListDatabases();
```

## Step 11: Delete all databases/the databases file
```csharp
Database.EnsureDeleted();
```

# Two factor authentication

You can use 2FA for making the login to the database more secure, 
but you can also use PassWords to validate a 2FA login into another system.

## Using 2FA in PassWords
```csharp
//First, login into your database
static Database db = new Database();
db.Login("YourDBName","YourPassword");

//Second, enable 2FA login
db.Add2FA();

//Third, get your secret
//Use this secret into another 2FA app
string secret = db.Get2FA();

//Logout