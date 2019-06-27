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

        //Private functions used for encryption
        private string Encrypt(string input){return new Easy.Encryption(Aes.Create(), _Password, _Salt).Encrypt(input);}
        private string Decrypt(string input) { return new Easy.Encryption(Aes.Create(), _Password, _Salt).Decrypt(input); }

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
            return a;
        }

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
                    _Salt = db.Name+"$*(!@#$)"+db.Name;

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
        /// <returns></returns>
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

            return true;
        }

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
        public string Get2FA() { return _Database.TwoFactorSecret; }


        //Two factor authentication helpers
        public static string GenerateCode(string secret){ return new TwoFactor(secret).GenerateCode(); }
        public static string GenerateSecret() { return TwoFactor.GenerateSecret(); }
        public static bool Validate2FA(string secret, string code){ return new TwoFactor(secret).ValidateCode(code); }
        

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
        /// <returns>True of it succeed, false if it failed</returns>
        public static bool Restore(string path)
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
                    context.Databases.Add(new DB {Name = "_"+obj.Database.Name, Passhash = obj.Database.Passhash, TwoFactorSecret = obj.Database.TwoFactorSecret });
                    var db = GetDB("_" + obj.Database.Name);
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

                if (acc.Count() == 0)
                    return null;

                if (encrypted)
                    return acc;
                else
                {
                    List<Account> unencrypted = new List<Account>();
                    foreach(var a in acc)
                    {
                       unencrypted.Add(Decrypt(a));
                    }
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
            if (oldpass == _Password)
            {
                using(var context = new PassContext())
                {
                    try
                    {
                        _Database.Passhash = Easy.Hashing.Hash(newpass);
                        /*var db = context.Databases.First(d => d.Id == _Database.Id);
                        db.Passhash = Easy.Hashing.Hash(newpass);
                        context.Databases.Update(db);
                        context.SaveChanges();
                        return UpdateEncryption(newpass);*/
                        context.Databases.Update(_Database);
                        context.SaveChanges();
                        return UpdateEncryption(newpass);
                    }
                    catch(Exception e) { Console.WriteLine(e.Message); return false; }
                }
            }
            else
                return false;
        }

        private bool UpdateEncryption(string newpass)
        {
            try
            {
                var acc = GetAccounts();
                _Password = newpass;
                foreach(var account in acc)
                {
                    Update(account);
                }
                return true;
            }
            catch(Exception e) { Console.WriteLine(e.Message); return false; }
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
        public static List<DB> ListDatabases()
        {
            using(var context = new PassContext())
            {
                return context.Databases.ToList();
            }
        }

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

                    DB d = new DB { Name = name, Passhash = Easy.Hashing.Hash(password) };

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

        private static bool AddRange(Account[] ac)
        {
            try
            {
                using (var context = new PassContext())
                {
                    foreach (var a in ac)
                    {
                        context.Accounts.Add(a);
                    }
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
                    context.Accounts.Update(acc);
                    context.SaveChanges();
                }
                return true;
            }
            catch(Exception e) { Console.WriteLine(e.Message); return false; }
        }
       
    }
}
