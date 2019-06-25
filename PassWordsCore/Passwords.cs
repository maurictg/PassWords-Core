using System;
using System.Linq;
using System.Text;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Collections.Generic;
using Newtonsoft.Json;
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
    }

    /// <summary>
    /// NO DATABASE CLASSES
    /// </summary>


    public enum LoginResult
    {
        Success, PasswordWrong, TooMuchTries, Error, Database_Not_Exist
    }

    public class Login
    {
        public int DbID { get; set; }
        public string Password { get; set; }
    }

    public class DBObject
    {
        public DB Database;
        public List<Account> Accounts;
    }

    public class Database
    {
        //ALWAYS CHECK IF THESE VALUES ARE ASSIGNED BEFORE FIRING FUCNTION!!
        private string _Password { get; set; }
        private string _Salt { get; set; }
        private int _Tries { get; set; }
        private DB _Database { get; set; }
        public bool _IsLoggedIn = false;

        private string Encrypt(string input){return new Easy.Encryption(Aes.Create(), _Password, _Salt).Encrypt(input);}
        private string Decrypt(string input) { return new Easy.Encryption(Aes.Create(), _Password, _Salt).Decrypt(input); }

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

        public LoginResult Login(string database, string password)
        {
            if (_Tries > 3)
                return LoginResult.TooMuchTries;

            var dbs = GetDB(database);
            if (dbs == null)
                return LoginResult.Database_Not_Exist;

            using (var context = new PassContext())
            {
                var db = context.Databases.First(d => d.Id == dbs.Id);
                if (Easy.Hashing.Verify(db.Passhash, password))
                { _Tries = 0; _Database = db; _Password = password; _Salt = db.Name+"$*(!@#$)"+db.Name; _IsLoggedIn = true; return LoginResult.Success; }
                else
                { _Tries++; return LoginResult.PasswordWrong; }
            }
        }

        public static void EnsureCreated() { new PassContext().Database.EnsureCreated(); }
        public static void EnsureDeleted() { new PassContext().Database.EnsureDeleted(); }

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

        public static bool Restore(string path)
        {
            if (!File.Exists(path))
                return false;

            try
            {
                string json = File.ReadAllText(path);
                var obj = JsonConvert.DeserializeObject<DBObject>(json);

                //Import database
                var db = obj.Database;

                if (CreateDB("_" + db.Name, db.Passhash))
                {
                    db = GetDB("_" + db.Name);
                    if(db != null)
                    {
                        List<Account> toadd = new List<Account>();
                        foreach(var a in obj.Accounts)
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
                else
                    return false;

            }
            catch (Exception e) { Console.WriteLine(e.Message); return false; }
        }

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

        public bool UpdatePassword(string oldpass, string newpass)
        {
            if (oldpass == _Password)
            {
                using(var context = new PassContext())
                {
                    try
                    {
                        var db = context.Databases.First(d => d.Id == _Database.Id);
                        db.Passhash = Easy.Hashing.Hash(newpass);
                        context.Update(db);
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

        public static List<DB> ListDatabases()
        {
            using(var context = new PassContext())
            {
                return context.Databases.ToList();
            }
        }

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
                    context.Update(acc);
                    context.SaveChanges();
                }
                return true;
            }
            catch(Exception e) { Console.WriteLine(e.Message); return false; }
        }
       
    }
}
