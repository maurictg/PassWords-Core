using Microsoft.VisualStudio.TestTools.UnitTesting;
using PassWordsCore;
using System.Collections.Generic;
using System.Linq;
using System;

namespace PassWordsTest
{
    [TestClass]
    public class PassWordsTest
    {
        Database db = new Database();

        [TestMethod]
        public void aTestCreate()
        {
            //Initialize and clear databases file
            Database.EnsureDeleted();
            Database.EnsureCreated();

            bool test = Database.CreateDB("TestDB", "test123");
            Console.WriteLine((test) ? "Database created successfully": "Creating db failed");

        }

        [TestMethod]
        public void bTestLogin()
        {
            aTestCreate();
            db = new Database();
            var r1 = db.Login("TestDB", "test1234"); //LoginResult.PasswordWrong
            var r2 = db.Login("TestDB", "test123"); //LoginResult.Success
        }

        [TestMethod]
        public void cTestAdd()
        {
            aTestCreate();
            db = new Database();
            db.Login("TestDB", "test123");
            if(db.Add(new Account
            {
                Title = "testaccount",
                Username = "test",
                Password = "test123",
                Description = "This is an test account",
                Type = "test",
                TwoFactorSecret = ""
            }) == false)
            {
                throw new ArgumentException("Adding failed");
            }
        }

        [TestMethod]
        public void dTestUpdate()
        {
            aTestCreate();
            db = new Database();
            db.Login("TestDB", "test123");
            if(db.Add(new Account()
            {
                Title = "testaccountl",
                Username = "test",
                Password = "test123",
                Description = "This is an test account",
                Type = "test",
                TwoFactorSecret = ""
            }) == false)
            {
                throw new ArgumentNullException("Adding failed");
            }

            var d = db.GetAccounts();
            var a = d.First(e => e.Title == "testaccountl");
            a.Username = "testje";
            a.Password = "test1234";
            db.Update(a);
        }

        [TestMethod]
        public void eTestDelete()
        {
            aTestCreate();
            db = new Database();
            db.Login("TestDB", "test123");
            db.Add(new Account
            {
                Title = "testaccount",
                Username = "test",
                Password = "test123",
                Description = "This is an test account",
                Type = "test"
            });
            Console.WriteLine(db.GetAccounts().Count());
            var a = db.GetAccounts().FirstOrDefault();
            db.Delete(a);
        }

        [TestMethod]
        public void fChangeName()
        {
            aTestCreate();
            db = new Database();
            db.Login("TestDB", "test123");
            Console.WriteLine(db.Name() + " changing to testjedb");
            Console.WriteLine(db.UpdateName("testjedb"));
        }

        [TestMethod]
        public void gTestBackup()
        {
            db = new Database();
            db.Login("testjedb", "test123");
            Console.WriteLine("Creating backup");
            Console.WriteLine(db.Backup(System.IO.Path.Combine(Environment.CurrentDirectory, "test.db")));
            Console.WriteLine("done");
        }

        [TestMethod]
        public void hTestRestore()
        {
            db = new Database();
            db.Login("testjedb", "test123");
            string name = db.Name();
            db.Logout();
            Database.DeleteDB(name);
            Database.Restore(System.IO.Path.Combine(Environment.CurrentDirectory, "test.db"), "test");
            db = new Database();
            db.Login("test","test123");
            Console.WriteLine(db.GetAccounts().Count());
        }

        [TestMethod]
        public void iTestChangePass()
        {
            aTestCreate();
            cTestAdd();
            db.Login("TestDB", "test123");
            Console.WriteLine("Changing password");

            if (!db.UpdatePassword("test123", "test1234"))
                throw new ArgumentException("Changing failed");

            db.Logout();
            if (db.Login("TestDB", "test1234") != LoginResult.Success)
                throw new ArgumentException("Loggin in failed");

            var a = db.GetAccounts();
            Console.WriteLine(a.Count());

        }
    }
}
