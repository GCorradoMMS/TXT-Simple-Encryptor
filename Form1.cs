using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO;

namespace APSTextEncrypter
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void EncryptBtn_Click(object sender, EventArgs e)
        {
            var choosenFile = string.Empty;

            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                string fileContent = "";
                string fileName = "";
                openFileDialog.InitialDirectory = "c:\\";
                openFileDialog.Filter = "File TXT(*.txt)|*.txt*.*";
                openFileDialog.FilterIndex = 2;
                openFileDialog.RestoreDirectory = true;

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    fileContent = openFileDialog.FileName;
                    fileName = openFileDialog.SafeFileName;
                }

                if (File.Exists(fileContent))
                {
                    string encryptStr = "";
                    string password = "1337";
                    using (StreamReader sr = new StreamReader(fileContent))
                    {
                        encryptStr = sr.ReadToEnd();
                    }
                    encryptStr = EncryptText(encryptStr, password);
                    WriteFile(encryptStr, fileName);

                }
            }
        }

        private void DecryptBtn_Click(object sender, EventArgs e)
        {
            var choosenFile = string.Empty;

            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                string fileContent = "";
                string fileName= "";
                openFileDialog.InitialDirectory = "c:\\";
                openFileDialog.Filter = "File TXT(*.txt)|*.txt*.*";
                openFileDialog.FilterIndex = 2;
                openFileDialog.RestoreDirectory = true;

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    fileContent = openFileDialog.FileName;
                    fileName = openFileDialog.SafeFileName;
                }

                if (File.Exists(fileContent))
                {
                    string decryptStr = "";
                    string password = "1337";
                    using (StreamReader sr = new StreamReader(fileContent))
                    {
                        decryptStr = sr.ReadToEnd();
                    }
                    decryptStr = DecryptText(decryptStr, password);
                    WriteFile(decryptStr, fileName);

                }

            }
        }
        
        public string EncryptText(string textData, string Encryptionkey)
        {

            RijndaelManaged objrij = new RijndaelManaged();
            objrij.Mode = CipherMode.CBC;
            objrij.Padding = PaddingMode.PKCS7;
            objrij.KeySize = 0x80;
            objrij.BlockSize = 0x80;
            byte[] passBytes = Encoding.UTF8.GetBytes(Encryptionkey);
            byte[] EncryptionkeyBytes = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            int len = passBytes.Length;
            if (len > EncryptionkeyBytes.Length)
            {
                len = EncryptionkeyBytes.Length;
            }
            Array.Copy(passBytes, EncryptionkeyBytes, len);
            objrij.Key = EncryptionkeyBytes;
            objrij.IV = EncryptionkeyBytes;
            ICryptoTransform objtransform = objrij.CreateEncryptor();
            byte[] textDataByte = Encoding.UTF8.GetBytes(textData);
            return Convert.ToBase64String(objtransform.TransformFinalBlock(textDataByte, 0, textDataByte.Length));
        }

        string DecryptText(string EncryptedText, string Encryptionkey)
        {
            RijndaelManaged objrij = new RijndaelManaged();
            objrij.Mode = CipherMode.CBC;
            objrij.Padding = PaddingMode.PKCS7;
            objrij.KeySize = 0x80;
            objrij.BlockSize = 0x80;
            byte[] encryptedTextByte = Convert.FromBase64String(EncryptedText);
            byte[] passBytes = Encoding.UTF8.GetBytes(Encryptionkey);
            byte[] EncryptionkeyBytes = new byte[0x10];
            int len = passBytes.Length;
            if (len > EncryptionkeyBytes.Length)
            {
                len = EncryptionkeyBytes.Length;
            }
            Array.Copy(passBytes, EncryptionkeyBytes, len);
            objrij.Key = EncryptionkeyBytes;
            objrij.IV = EncryptionkeyBytes;
            byte[] TextByte = objrij.CreateDecryptor().TransformFinalBlock(encryptedTextByte, 0, encryptedTextByte.Length);
            return Encoding.UTF8.GetString(TextByte);  //it will return readable string
        }

        private static byte[] Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;

            var saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);

                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }

                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }

        private static byte[] Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;
            var saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);

                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);
                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }

                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }

        public void WriteFile(string contents, string fileName)
        {
            string path = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)+"\\"+fileName;
            MessageBox.Show(path);
            File.WriteAllText(path, contents);
            string readText = File.ReadAllText(path);
        }

        private void toolStripMenuItem1_Click(object sender, EventArgs e)
        {
            
        }

        private void créditosToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string credits = +"Gustavo Corrado"
                             +"Information Security college project\n" +
                             "Information Systems - 4 semester.\n"/
            MessageBox.Show(credits, "Credits");
        }

        private void informaçãoToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string info = "APSTextEncrypter 1.0\n"
                            + "Made using C# (.NET Framework) for Windows Platforms\n"
                            +"Encrypted and decrypted files are located in the Documents folder;";
            MessageBox.Show(info, "About");
        }

        private void label1_Click(object sender, EventArgs e)
        {

        }
    }
}
