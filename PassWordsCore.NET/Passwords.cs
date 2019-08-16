/*  
 *  Copyright (c) 2019 MaurICT
 *  
 *  Permission is hereby granted, free of charge, to any person obtaining a copy of this
 *  software and associated documentation files (the "Software"), to deal in the Software
 *  without restriction, including without limitation the rights to use, copy, modify, merge,
 *  publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
 *  to whom the Software is furnished to do so, subject to the following conditions:
 *  
 *  The above copyright notice and this permission notice shall be included in all copies or
 *  substantial portions of the Software.
 *  
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 *  INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 *  PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
 *  FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 *  OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 */


using System;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Collections.Generic;
using Newtonsoft.Json;
using TwoFactorAuthentication;
using System.IO;

namespace PassWordsCore
{
    public class PassContext: DbContext
    {
        public DbSet<DB> Databases { get; set; }
        public DbSet<Account> Accounts { get; set; }
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlite($"Data Source={Path.Combine(Environment.CurrentDirectory,"Passwords.epwd")}");
        }
    }

    public class DB
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Passhash { get; set; }
        public string Salt { get; set; }
        public string TwoFactorSecret { get; set; }
    }

    public class Account
    {
        public int Id { get; set; }
        public int DbID { get; set; }
        public string Title { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Description { get; set; }
        public string Type { get; set; }
        public string TwoFactorSecret { get; set; }
    }

    //No database classes
    /// <summary>
    /// enum used for verifying login
    /// </summary>
    public enum LoginResult
    {
        Success, PasswordWrong, TooMuchTries, Error, Database_Not_Exist, Needs2FA
    }

    /// <summary>
    /// Object used for export/importing databases
    /// </summary>
    public class DBObject
    {
        public DB Database;
        public List<Account> Accounts;
    }

    /// <summary>
    /// The object used for communicating to a virtual database
    /// </summary>
    public class Database
    {
        //ALWAYS CHECK IF THESE VALUES ARE ASSIGNED BEFORE FIRING FUCNTION!!

        private string _Password { get; set; }
        private string _Salt { get; set; }
        private int _Tries { get; set; }
        private DB _Database { get; set; }

        private bool _IsLoggedIn = false;
        private bool _Needs2FA = false;

        private Easy.Encryption _Encryption { get; set; }

        //Private functions used for encryption
        private string Encrypt(string input) => _Encryption.Encrypt(input);
        private string Decrypt(string input) => _Encryption.Decrypt(input); 

        //Private function used to encrypt an account
        private Account Encrypt(Account a)
        {
            if (!_IsLoggedIn)
                return null;

            a.DbID = _Database.Id;
            a.Title = Encrypt(a.Title);
            a.Username = Encrypt(a.Username);
            a.Password = Encrypt(a.Password);
            a.Description = Encrypt(a.Description);
            a.TwoFactorSecret = Encrypt(a.TwoFactorSecret);
            return a;
        }

        //Private function used to decrypt an account
        private Account Decrypt(Account a)
        {
            if (!_IsLoggedIn)
                return null;

            a.DbID = _Database.Id;
            a.Title = Decrypt(a.Title);
            a.Username = Decrypt(a.Username);
            a.Password = Decrypt(a.Password);
            a.Description = Decrypt(a.Description);
            a.TwoFactorSecret = Decrypt(a.TwoFactorSecret);
            return a;
        }

        //To get some property's when signed in
        /// <summary>
        /// Returns the name of the current databse
        /// </summary>
        /// <returns>string name, if null: you are not logged in</returns>
        public string Name() => _Database.Name;


        /// <summary>
        /// Opens and verifys an virtual database
        /// </summary>
        /// <param name="database">The name of the virtual database you want to open</param>
        /// <param name="password">The password used for encryption</param>
        /// <returns>LoginResult</returns>
        public LoginResult Login(string database, string password)
        {
            if (_Tries > 10)
                return LoginResult.TooMuchTries;

            var dbs = GetDB(database);
            if (dbs == null)
                return LoginResult.Database_Not_Exist;

            using (var context = new PassContext())
            {
                var db = context.Databases.First(d => d.Id == dbs.Id);
                if (Easy.Hashing.Verify(db.Passhash, password))
                {
                    _Tries = 0;
                    _Database = db;
                    _Password = password;
                    _Salt = db.Salt;
                    _Encryption = new Easy.Encryption(Aes.Create(), _Password, _Salt, 10000);

                    if (!string.IsNullOrEmpty(db.TwoFactorSecret))
                    {
                        _Needs2FA = true;
                        return LoginResult.Needs2FA;
                    }

                    _IsLoggedIn = true;
                    return LoginResult.Success;
                }
                else
                { _Tries++; return LoginResult.PasswordWrong; }
            }
        }

        /// <summary>
        /// Logs the current db out
        /// </summary>
        /// <returns>false if already logged out, else true</returns>
        public bool Logout()
        {
            if (!_IsLoggedIn)
                return false;

            _Password = null;
            _Salt = null;
            _Tries = 0;
            _Database = null;
            _Needs2FA = false;
            _IsLoggedIn = false;
            _Encryption = null;

            return true;
        }

        /// <summary>
        /// Validates the 2fa code to login into the database
        /// </summary>
        /// <param name="code">The 6-digit validation code</param>
        /// <returns>True or false, when true: database is logged in</returns>
        public bool Login2FA(string code)
        {
            if (!_Needs2FA)
                return false;

            //Validate
            if (!Validate2FA(_Database.TwoFactorSecret, code))
                return false;

            _Needs2FA = false;
            _IsLoggedIn = true;
            return true;
        }


        /// <summary>
        /// Adds TwoFactorAuthentication to current database
        /// </summary>
        /// <returns>True or false</returns>
        public bool Add2FA()
        {
            if (!_IsLoggedIn)
                return false;

            _Database.TwoFactorSecret = GenerateSecret();

            using(var context = new PassContext())
            {
                context.Databases.Update(_Database);
                context.SaveChanges();
                return true;
            }
        }

        /// <summary>
        /// Remove TwoFactorAuthentication from current database
        /// </summary>
        /// <returns>True or false</returns>
        public bool Remove2FA()
        {
            if (!_IsLoggedIn)
                return false;

            if (string.IsNullOrEmpty(_Database.TwoFactorSecret))
                return false;

            _Database.TwoFactorSecret = string.Empty;

            using (var context = new PassContext())
            {
                context.Databases.Update(_Database);
                context.SaveChanges();
                return true;
            }
        }

        /// <summary>
        /// Returns current database 2FA secret
        /// </summary>
        /// <returns>Secret (string)</returns>
        public string Get2FA() => _Database.TwoFactorSecret;


        //Two factor authentication helpers
        /// <summary>
        /// Generates a 2fa authentication code
        /// </summary>
        /// <param name="secret">The secret</param>
        /// <returns>A string, the 6-digit code</returns>
        public static string GenerateCode(string secret) => new TwoFactor(secret).GenerateCode();
        /// <summary>
        /// Generates a new 2fa secret
        /// </summary>
        /// <returns>A new secret</returns>
        public static string GenerateSecret() => TwoFactor.GenerateSecret(); 
        /// <summary>
        /// Validates if 2fa code is correct with the secret
        /// </summary>
        /// <param name="secret">The secret</param>
        /// <param name="code">The 6-digit validation code</param>
        /// <returns>True or false</returns>
        public static bool Validate2FA(string secret, string code) => new TwoFactor(secret).ValidateCode(code);

        private static Random _Random = new Random();
        /// <summary>
        /// Generate a random string
        /// </summary>
        /// <param name="length">The length of the string</param>
        /// <param name="letters">If you want to use lowercase letters</param>
        /// <param name="captials">If you want to use uppercase letters</param>
        /// <param name="numbers">If you want to use numbers</param>
        /// <param name="special">If you want to use special chars</param>
        /// <returns>A random string</returns>
        public static string RandomString(int length, bool letters = true, bool captials = false, bool numbers = false, bool special = false)
        {
            const string scaptials = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string snumbers = "0123456789";
            const string sletters = "abcdefghijklmnopqrstuvwxyz";
            const string sspecial = "!@#$%^&*()-=_+;<>?,.{}[]";

            string chars = "";
            if (letters)
                chars += sletters;
            if (captials)
                chars += scaptials;
            if (numbers)
                chars += snumbers;
            if (special)
                chars += sspecial;

            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[_Random.Next(s.Length)]).ToArray());
        }


        /// <summary>
        /// Creates the database file in which te virtual databases are stored if it does not exist
        /// </summary>
        public static void EnsureCreated() => new PassContext().Database.EnsureCreated();
        /// <summary>
        /// Deletes the database file in which te virtual databases are stored if it does exist
        /// </summary>
        public static void EnsureDeleted() => new PassContext().Database.EnsureDeleted();

        /// <summary>
        /// Make a backup of an virtual database
        /// </summary>
        /// <param name="destination">The file that will be created. Suggest to end with .pwdb</param>
        /// <returns>False if it failed, true if it succeed</returns>
        public bool Backup(string destination)
        {
            if (!_IsLoggedIn)
                return false;

            try
            {
                string json = JsonConvert.SerializeObject(new DBObject { Accounts = GetAccounts(true), Database = _Database });
                File.WriteAllText(destination, json);
                return true;
            }
            catch(Exception e) { Console.WriteLine(e.Message); return false; }
        }

        /// <summary>
        /// Restores an virtual database into your database
        /// </summary>
        /// <param name="path">The path of your database</param>
        /// <param name="name">The name you want to use for the database</param>
        /// <returns>True of it succeed, false if it failed</returns>
        public static bool Restore(string path, string name)
        {
            if (!File.Exists(path))
                return false;

            try
            {
                string json = File.ReadAllText(path);
                var obj = JsonConvert.DeserializeObject<DBObject>(json);

                //Import database
                using(var context = new PassContext())
                {
                    string newname = (string.IsNullOrEmpty(name)) ? "_" + obj.Database.Name : name;
                    context.Databases.Add(new DB {Name = newname, Passhash = obj.Database.Passhash, TwoFactorSecret = obj.Database.TwoFactorSecret, Salt = obj.Database.Salt });
                    context.SaveChanges();
                    var db = GetDB(newname);
                    if (db != null)
                    {
                        List<Account> toadd = new List<Account>();
                        foreach (var a in obj.Accounts)
                        {
                            a.DbID = db.Id;
                            toadd.Add(a);
                        }

                        return AddRange(toadd.ToArray());
                    }
                    else
                    {
                        Console.WriteLine("ERROR: DB NOT FOUND");
                        return false;
                    }
                }
            }
            catch (Exception e) { Console.WriteLine(e.Message); return false; }
        }

        /// <summary>
        /// Get a list of all accounts stored into a virtual database
        /// </summary>
        /// <param name="encrypted">Identifies if you want encrypted records. They're useless by the way</param>
        /// <returns>List of accounts</returns>
        public List<Account> GetAccounts(bool encrypted = false)
        {
            using(var context = new PassContext())
            {
                var acc = context.Accounts.Where(d => d.DbID == _Database.Id).ToList();

                if (acc == null)
                    throw new ArgumentNullException("No accounts found");
                //if (acc.Count() == 0)
                 //   return null;

                if (encrypted)
                    return acc;
                else
                {
                    List<Account> unencrypted = new List<Account>();
                    foreach(var a in acc)
                       unencrypted.Add(Decrypt(a));

                    return unencrypted;
                }
            }
        }

        /// <summary>
        /// Updates the password of a virtual database
        /// </summary>
        /// <param name="oldpass">The current password</param>
        /// <param name="newpass">The new password</param>
        /// <returns>False if the current pass is wrong or it failed, true if it succeed</returns>
        public bool UpdatePassword(string oldpass, string newpass)
        {
            try
            {
                var accounts = GetAccounts();
                if (oldpass == _Password)
                {
                    using (var context = new PassContext())
                    {
                        //try
                        //{
                            _Database.Passhash = Easy.Hashing.Hash(newpass);
                            _Password = newpass;
                            _Encryption = new Easy.Encryption(Aes.Create(), _Password, _Salt, 10000);

                            context.Databases.Update(_Database);
                            context.SaveChanges();

                        //try
                        //{
                        foreach (var account in accounts)
                            if (!Update(account))
                                throw new ArgumentException("Updating an entry failed");

                        return true;
                        //}
                        //catch (Exception e) { Console.WriteLine(e.Message); return false; }

                        //}
                        //catch(Exception e) { Console.WriteLine(e.Message); return false; }
                    }
                }
                else
                    return false;
            }
            catch(Exception e)
            {
                throw e;
            }

            
        }

        /// <summary>
        /// Updates the name of the database
        /// </summary>
        /// <param name="newname">The new name for the database</param>
        /// <returns>bool</returns>
        public bool UpdateName(string newname)
        {
            if (string.IsNullOrEmpty(newname))
                return false;

            var current = GetDB(_Database.Name);
            current.Name = newname;

            try
            {
                using (var context = new PassContext())
                {
                    context.Databases.Update(current);
                    context.SaveChanges();
                    _Database = GetDB(current.Name);
                }

                return true;
            }
            catch(Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        //Get the database object by name
        private static DB GetDB(string name)
        {
            using(var context = new PassContext())
            {
                if (context.Databases.Any(d => d.Name == name))
                    return context.Databases.First(d => d.Name == name);
                else
                    return null;
            }
        }

        /// <summary>
        /// List all virtual databases in your database
        /// </summary>
        /// <returns>List of databases</returns>
        public static List<DB> ListDatabases() =>  new PassContext().Databases.ToList();

        /// <summary>
        /// Create a new virtual database into your database
        /// </summary>
        /// <param name="name">The name. This must be unique</param>
        /// <param name="password">The password used for authentication and encryption</param>
        /// <returns>false if name is in use or it failed, true if it succeed</returns>
        public static bool CreateDB(string name, string password)
        {
            try
            {
                using (var context = new PassContext())
                {
                    if (context.Databases.Any(e => e.Name == name))
                        return false;

                    DB d = new DB { Name = name, Passhash = Easy.Hashing.Hash(password), Salt = $"A{name}$*(!@#$){name}a" };

                    context.Databases.Add(d);
                    context.SaveChanges();
                }
                return true;
            }
            catch(Exception e) { Console.WriteLine(e.Message); return false; }
        }

        /// <summary>
        /// Delete a virtual database from your database
        /// </summary>
        /// <param name="name">The name of the database</param>
        /// <returns>True if it succeed, false if it failed</returns>
        public static bool DeleteDB(string name)
        {
            try
            {
                using (var context = new PassContext())
                {
                    var db = context.Databases.First(e => e.Name == name);
                    context.Remove(db);
                    var accounts = context.Accounts.Where(a => a.DbID == db.Id);
                    context.Accounts.RemoveRange(accounts);
                    context.SaveChanges();
                }
                return true;
            }
            catch { return false; }
        }

        //Add a range of accounts
        private static bool AddRange(Account[] ac)
        {
            try
            {
                using (var context = new PassContext())
                {
                    foreach (var a in ac)
                        context.Accounts.Add(a);

                    context.SaveChanges();
                    return true;
                }
            }
            catch (Exception e) { Console.WriteLine(e.Message); return false; }
        }
       
        /// <summary>
        /// Add an account to the database
        /// </summary>
        /// <param name="a">The account object</param>
        /// <returns>True or false</returns>
        public bool Add(Account a)
        {
            try
            {
                using (var context = new PassContext())
                {
                    a.DbID = _Database.Id;
                    context.Accounts.Add(Encrypt(a));
                    context.SaveChanges();
                }
                return true;
            }
            catch(Exception e) { Console.WriteLine(e.Message); return false; }
        }

        /// <summary>
        /// Remove an account from the database
        /// </summary>
        /// <param name="a"></param>
        /// <returns>True or false</returns>
        public bool Delete(Account a)
        {
            try
            {
                using (var context = new PassContext())
                {
                    var acc = context.Accounts.First(e => e.Id == a.Id);
                    context.Accounts.Remove(acc);
                    context.SaveChanges();
                }
                return true;
            }
            catch(Exception e) { Console.WriteLine(e.Message);  return false; }
        }

        /// <summary>
        /// Updates an account in the database
        /// </summary>
        /// <param name="a">The account object</param>
        /// <returns>True or false</returns>
        public bool Update(Account a)
        {
            try
            {
                using (var context = new PassContext())
                {
                    var acc = context.Accounts.First(b => b.Id == a.Id);
                    a = Encrypt(a);
                    acc.Username = a.Username;
                    acc.Password = a.Password;
                    acc.Description = a.Description;
                    acc.Title = a.Title;
                    acc.Type = a.Type;
                    acc.TwoFactorSecret = a.TwoFactorSecret;
                    context.Accounts.Update(acc);
                    context.SaveChanges();
                }
                return true;
            }
            catch(Exception e) { Console.WriteLine(e.Message); return false; }
        }
       
    }
}
