using System;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using MySql.Data.MySqlClient;
using Pass_Manager;

namespace Pass_Manger
{
    /*
     * The prototype will use functions as different "states"
    */ 
    class Program
    {
        static void Main(string[] args)
        {
            if (RetrieveMasterPass() == "") { CreateMasterPass(); }
            if (Login()) { Landing(); }
            else
            {
                Console.WriteLine("That is incorrect. Now Exiting");
                Environment.Exit(0);
            }
        }
        static void CreateMasterPass()
        {
            string password = "";
            string encryptedPassword = "";
            string salt = Convert.ToBase64String(Encryption.GenerateSalt());
            Console.WriteLine("Please enter your desired master password");
            password = Encryption.KeyMask();

            encryptedPassword = Encryption.EncryptPassword_PBKDF2(password, Convert.FromBase64String(salt));

            InsertMasterPassHash(encryptedPassword, salt);
            Console.WriteLine("\nPassword entered thank you");
        }
        static bool Login()
        {
            // Opening sequance
            Console.WriteLine("Welcome Dakota\nPlease enter your password");
            string input = "";
            input = Encryption.KeyMask();
            string encryptedInput = "";
            string masterPass = "";

            // Check for match
            masterPass = RetrieveMasterPass();
            encryptedInput = Encryption.EncryptPassword_PBKDF2(input, Convert.FromBase64String(GetMasterSalt()));

            if(masterPass == encryptedInput) { return true; }
            return false;
        }
        static void Landing()
        {
            Console.Clear();
            Console.WriteLine("What would you like to do?");
            Console.WriteLine("[1] Get Password\n[2] Add Service\n[3] Exit\n");

            string input = Console.ReadLine();
            switch (input)
            {
                case "1": GetPassword(); break;
                case "2": AddService(); break;
                case "3": Environment.Exit(0); break;
            }
        }
        static void GetPassword()
        {
            /*
             * Get the password, salt, and Iv from the DB with provided service name
             * Generate encryption key
             * use information for decryption
             * remove the salt from the password
             * display the password
             * Allow the user to enter "3" to return
            */
            string service = "";
            string cipherText = "";
            string salt = "";
            string iv = "";

            Console.Clear();
            // Get an email and master password
            Console.WriteLine("Please enter an email.\n");
            string email = Console.ReadLine();
            Console.WriteLine("\nPlease Enter the master password.\n");
            string masterPassword = "";
            masterPassword = Encryption.KeyMask();

            Console.Clear();
            Console.WriteLine("Please enter 3 if you are in the wrong menu. \nWhat service would you like the passwor for?\n");
            service = Console.ReadLine();
            if (service == "3") { Landing(); }

            RetrieveService(service, ref cipherText, ref salt, ref iv);

            string password = Encryption.DecryptPassword_AES(cipherText, Encryption.GenerateKey(email, masterPassword, Convert.FromBase64String(salt)), iv);

            // Remove the salt from the password by knowing all passwords are generated with 15 characters before the salt is added
            password = password.Remove(14);
            Console.Clear();
            Console.WriteLine($"Service: {service}\nPassword: {password}");

            // Exit
            Console.WriteLine("\n\nIf you are finished enter 3\n");
            if (Console.ReadLine() == "3") { Landing(); }
        }
        static void AddService()
        {
            string serviceName = "";
            string password = "";
            string salt = "";
            string IV = "";

            Console.Clear();
            Console.WriteLine("You have chosen to add a service. If this is wrong please enter 3.\nEnter name for the service:\n");
            serviceName = Console.ReadLine();
            serviceName = serviceName.ToLower();

            if (serviceName == "3") { Landing(); }

            /*
             * Generate a password
             * Display that password
             * Generate Encryption key
             * Add salt
             * Encrypt using AES
             * Save encrypted password to DB along with salt and IV
             * Save service name
            */

            // Get the user to re-enter their master password and an email
            Console.WriteLine("\nNow enter an email\n");
            string email = Console.ReadLine();
            Console.WriteLine("\nPlease enter the master password.\n");
            string masterPass = "";
            masterPass = Encryption.KeyMask();

            password = Encryption.GenerateRandomPassword();
            Console.WriteLine($"Password: {password}");
            
            salt = Convert.ToBase64String(Encryption.GenerateSalt());
            IV = Convert.ToBase64String(Encryption.GenerateIv());

            string saltedPassword = password + salt;

            string encryptedPassword = Encryption.EncryptPassword_AES(saltedPassword, Encryption.GenerateKey(email, masterPass, Convert.FromBase64String(salt)), IV);

            InsertService(serviceName, encryptedPassword, salt, IV);

            // Exit this menu
            Console.WriteLine("\nPlease enter 3 when ready to return.\n");
            if(Console.ReadLine() == "3") { Landing(); }
        }

        // DB Access
        static void InsertMasterPassHash(string password, string salt)
        {
            MySqlConnection cnn;
            string connectionString = Environment.GetEnvironmentVariable("Connection String");
            cnn = new MySqlConnection(connectionString);
            try
            {
                MySqlCommand cmd = cnn.CreateCommand();
                cmd.Connection = cnn;
                cmd.CommandText = $"INSERT INTO userpass (Password, Salt) VALUES('{password}', '{salt}');";

                cnn.Open();
                cmd.ExecuteNonQuery();
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                cnn.Close();
            }
        }
        static string RetrieveMasterPass()
        {
            string password = "";
            MySqlConnection cnn;
            string connectionString = Environment.GetEnvironmentVariable("Connection String");
            cnn = new MySqlConnection(connectionString);
            try
            {
                MySqlCommand mySqlCommand = cnn.CreateCommand();
                mySqlCommand.Connection = cnn;
                mySqlCommand.CommandText = "SELECT Password FROM userpass;";

                cnn.Open();
                using var myReader = mySqlCommand.ExecuteReader();
                myReader.Read();
                password = myReader.GetString("Password");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                cnn.Close();
            }
            return password;
        }
        static string GetMasterSalt()
        {
            string salt = "";
            MySqlConnection cnn;
            string connectionString = Environment.GetEnvironmentVariable("Connection String");
            cnn = new MySqlConnection(connectionString);
            try
            {
                MySqlCommand cmd = cnn.CreateCommand();
                cmd.Connection = cnn;
                cmd.CommandText = $"SELECT Salt FROM userpass";

                cnn.Open();
                var myReader = cmd.ExecuteReader();
                myReader.Read();
                salt = myReader.GetString("Salt");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                cnn.Close();
            }
            return salt;
        }
        static void InsertService(string service, string encryptedPass, string salt, string Iv)
        {
            MySqlConnection cnn;
            string ConnectionString = Environment.GetEnvironmentVariable("Connection String");
            cnn = new MySqlConnection(ConnectionString);
            try
            {
                MySqlCommand cmd = cnn.CreateCommand();
                cmd.Connection = cnn;
                cmd.CommandText = $"INSERT INTO services (Service, Password, Salt, IV) VALUES('{service}', '{encryptedPass}', '{salt}', '{Iv}')";

                cnn.Open();
                cmd.ExecuteNonQuery();
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                cnn.Close();
            }
        }
        static void RetrieveService(string service,ref string cipherString, ref string salt, ref string iv)
        {
            service = service.ToLower();
            MySqlConnection cnn;
            string connectionString = Environment.GetEnvironmentVariable("Connection String");
            cnn = new MySqlConnection(connectionString);
            try
            {
                MySqlCommand cmd = cnn.CreateCommand();
                cmd.Connection = cnn;
                cmd.CommandText = $"SELECT * FROM services WHERE Service='{service}'";

                cnn.Open();
                var myReader = cmd.ExecuteReader();
                myReader.Read();
                cipherString = myReader.GetString("Password");
                salt = myReader.GetString("Salt");
                iv = myReader.GetString("IV");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                cnn.Close();
            }
        }
    }
}