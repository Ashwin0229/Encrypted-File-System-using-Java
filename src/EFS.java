/*
 * @author Ashwin Sai C
 * @netid  axc210110
 * @email  axc210110@utdallas.edu
 */



import java.io.*;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
 
 public class EFS extends Utility 
     {
     
        int USER_NAME_LENGTH       = 128;
        int PASSWORD_LENGTH        = 32;
        int PASSWORD_PAD_LEN       = 128;
        int SALT_LENGTH            = 16;
        int HEADER_SIZE            = USER_NAME_LENGTH + PASSWORD_LENGTH + SALT_LENGTH;
        int SECRET_DATA_LENGTH     = 384;
        int METADATA_DATA_LENGTH   = HEADER_SIZE+SECRET_DATA_LENGTH;
        int HMAC_SIZE              = 32;       
        int SECRET_BLOCK_SIZE      = 560;
     
        public EFS(Editor e) 
             {
                 super(e);
                 set_username_password();
             }
        
        public void Check_Password(byte[] metadata, String password) throws Exception
            /*
                Parameters  : metadata, password
                Description : This function is used to check for the correct password and throws Exception.                            

                return      : None
            */
            {
                if (!Validate_Password(metadata, password))
                      {
                            throw new PasswordIncorrectException();
                      }
            }

        public byte[] Create_MetaData(byte[] header_data, byte[] enc_secret_data) 
            /*
                Parameters  : encrypted secret data, header data
                Description : This function is used to combine the encrypted secret data and header data into
                              a single Byte array.

                return      : metadata array
            */

             {
                ByteArrayOutputStream out   = new ByteArrayOutputStream();
                
                
                try 
                    {
                        out.write(header_data);
                        out.write(enc_secret_data);
                    } 
                catch (IOException e) 
                    {
                        e.printStackTrace();
                    }                
                byte[] meta_data_byte_array = out.toByteArray();
                return meta_data_byte_array;
             }    

        public void Write_ESD_HMAC(byte[] enc_secret_data, byte[] hmac_array, File file_handle, int Final_Block) throws Exception 
            /*
                Parameters  : encrypted secret data, hmac array, file handle and final block
                Description : This function is used to combine the encrypted secret data and HMAC into
                              a single Byte array and save it to a file handle.

                return      : None
            */

            {
                byte[] esd_hmac_array = new byte[enc_secret_data.length + hmac_array.length];

                System.arraycopy(enc_secret_data, 0, esd_hmac_array, 0, enc_secret_data.length);
                System.arraycopy(hmac_array, 0, esd_hmac_array, enc_secret_data.length, hmac_array.length);

                byte[] final_Padded_array = Padding_Algorithm(esd_hmac_array, 1024);

                save_to_file(final_Padded_array, new File(file_handle, Integer.toString(Final_Block + 1)));
            }

        public byte[] Read_File_Content(File file_handle, int Final_Block, int Block_size) throws Exception 
             /*
                Parameters  : file handle, final block and block size
                Description : This function is used to read the file content from the given file handle 
                              and return the content.

                return      : file content
            */

            {
                byte[] file_data         = read_from_file(new File(file_handle, Integer.toString(Final_Block + 1)));
                byte[] file_data_content = Arrays.copyOfRange(file_data, 0, Block_size);
                
                //unpad
                return file_data_content;
            }        

        public byte[] Extract_Salt(byte[] metadata_array)
            /*
                Parameters  : metadata array block
                Description : This function is used to extract the salt value from the metadata block.                              

                return      : password salt
            */

            {
                byte[] password_salt = Arrays.copyOfRange(metadata_array, USER_NAME_LENGTH + PASSWORD_LENGTH, HEADER_SIZE);
                return password_salt;
            }
         
        public byte[] Append_Metadata_HMAC(byte[] meta_data_array, byte[] hmac_array) 
             /*
                Parameters  : metadata and hmac
                Description : This function is used to append HMAC at the end of Metadata Array

                return      : output array
            */ 

            {
                byte[] output_array = new byte[meta_data_array.length +"\n".getBytes().length+ HMAC_SIZE];
                System.arraycopy(meta_data_array, 0, output_array, 0, meta_data_array.length);
                System.arraycopy("\n".getBytes(), 0, output_array, meta_data_array.length, "\n".length());
                System.arraycopy(hmac_array, 0, output_array, meta_data_array.length+"\n".length(), HMAC_SIZE);
               
                return output_array;
            }

        public byte[] longToBytes(long input)
            /*
                Parameters  : input
                Description : This function is used to convert long to Bytes array

                return      : byte array
            */

            {
                //remove
                 ByteBuffer bf = ByteBuffer.allocate(Long.BYTES);
                 bf.putLong(input);
                 
                 return bf.array();
            }
         
        public long bytesToLong(byte[] bytes)
            /*
                Parameters  : bytes
                Description : This function is used to convert byte array to long

                return      : long
            */

            {
                //remove
                 ByteBuffer bf = ByteBuffer.wrap(bytes);
                 
                 return bf.getLong();
            }

        public String Append_Padding(String str, int pad_length)
            /*
                Parameters  : str and length
                Description : This function is used to pad the str to the required length

                return      : padded data str
            */ 

            {
                 StringBuilder padded_data = new StringBuilder(str);
                 
                 while (padded_data.length() < pad_length)
                     {
                         padded_data.append('\0');
                     }

                 String padded_data_str = padded_data.toString();
                 //return padded_data.toString();

                 return padded_data_str;
            }
         
        public byte[] Block_Padding(byte[] data_blocks, int blockSize)
            /*
                Parameters  : data blocks and block size
                Description : This function is used to pad the blocks as per data size

                return      : padded data block
            */ 

            {
                 int pad_value     = blockSize - (data_blocks.length % blockSize);
                 byte[] padded_block = new byte[data_blocks.length + pad_value];
                 System.arraycopy(data_blocks, 0, padded_block, 0, data_blocks.length);
                 for (int i = data_blocks.length; i < padded_block.length; i++) 
                     {
                         padded_block[i] = (byte) pad_value;
                     }
                 return padded_block;
            }

        public static byte[] Padding_Algorithm(byte[] message, int blockSize)
            /*
                Parameters  : str message and block size
                Description : This function is used to pad the blocks with ISO
                              (Standard Algorithm)

                return      : padded message
            */
           
            {
                 int paddingLength    = blockSize - (message.length % blockSize);
                 byte[] paddedMessage = new byte[message.length + paddingLength];
                 System.arraycopy(message, 0, paddedMessage, 0, message.length);
                 paddedMessage[message.length] = (byte) 0x80;
                 for (int i = message.length + 1; i < paddedMessage.length; i++) 
                     {
                         paddedMessage[i] = 0x00;
                     }
                 
                 return paddedMessage;
            }

        public void updateMetadata(int length, byte[] metadata, String file_name) throws Exception
            /*
                Parameters  : file name
                Description : This function is used to update the metadata content of the file
                
                return      : None
            */

            {

                byte[] file_len               = longToBytes(length);
                byte[] hashed_salted_password = Arrays.copyOfRange(metadata, USER_NAME_LENGTH, USER_NAME_LENGTH + PASSWORD_LENGTH);
                byte[] meta_secret_data       = new byte[hashed_salted_password.length + file_len.length];
            
                int secret_data_idx = 0;
                for (byte b : hashed_salted_password)
                    {
                        meta_secret_data[secret_data_idx++] = b;
                    }
                for (byte b : file_len)
                    {
                        meta_secret_data[secret_data_idx++] = b;
                    }

                meta_secret_data             = Block_Padding(meta_secret_data, SECRET_DATA_LENGTH);            
                byte[] salt                  = Extract_Salt(metadata);                
                byte[] pwd_key               = Generate_Key(Append_Padding(password, PASSWORD_PAD_LEN), salt);
                byte[] encrypted_secret      = encript_AES(meta_secret_data, pwd_key);
                byte[] header                = Arrays.copyOfRange(metadata, 0, HEADER_SIZE);
                byte[] meta_data             = new byte[header.length + encrypted_secret.length];
                meta_data                    = Create_MetaData(header,encrypted_secret);            
                byte[] hmac                  = Generate_HMAC(meta_data);
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                byte[] combine_data          = Append_Metadata_HMAC(meta_data,hmac);
                byte[] padding               = Padding_Algorithm(combine_data, 1024);

                output.write(padding);

                byte[] outputBytes           = output.toByteArray();            
                File dir                     = new File(file_name);
                File metadata_file           = new File(dir, "0");

                save_to_file(outputBytes, metadata_file);
             }
                      
        public byte[] Generate_Key(String password, byte[] salt) throws Exception
             /*
                Parameters  : password and salt
                Description : This function is used to generate the key from password and salt for encrypt and decrypt                              
                
                return      : key
            */

             {                            

                 String padded_password         = Append_Padding(password, PASSWORD_PAD_LEN);
                 byte[] padded_password_Bytes   = padded_password.getBytes();
                 byte[] result_array            = new byte[padded_password_Bytes.length + salt.length];
         
                 System.arraycopy(padded_password_Bytes, 0, result_array, 0, padded_password_Bytes.length);
                 System.arraycopy(salt, 0, result_array, padded_password_Bytes.length, salt.length);
                 byte[] password_key            = hash_SHA512(result_array);                 

                 byte[] password_key_32_byte    = new byte[PASSWORD_LENGTH];
                 System.arraycopy(password_key, 0, password_key_32_byte, 0, PASSWORD_LENGTH);

                 return password_key_32_byte;
             }
         
        public byte[] Generate_Password_Hash(String password, byte[] salt) throws Exception 
              /*
                Parameters  : password and salt
                Description : This function is used to generate Password Hash
                
                return      : Password hash
              */
            {
                 String padded_password         = Append_Padding(password, PASSWORD_PAD_LEN);
                 byte[] padded_password_Bytes   = padded_password.getBytes();
                 byte[] result_array            = new byte[padded_password_Bytes.length + salt.length];
         
                 System.arraycopy(padded_password_Bytes, 0, result_array, 0, padded_password_Bytes.length);
                 System.arraycopy(salt, 0, result_array, padded_password_Bytes.length, salt.length);
         
                 byte[] password_hash           = hash_SHA256(result_array);
         
                 return password_hash;
             }
         
        public byte[] Fetch_MetaData(String file_name) throws Exception
            /*
                Parameters  : file name
                Description : This function is used to retrieve the metadata from file
                
                return      : metadata
            */

            {
                 File dir_handle                = new File(file_name);
                 File file_handle               = new File(dir_handle, "0");
                 FileInputStream file_data      = new FileInputStream(file_handle);
                 byte[] metadata                = file_data.readAllBytes();
                 
                 return metadata;
            }

        @Override
        public void create(String file_name, String user_name, String password) throws Exception
             /*
                Parameters  : file_name, username, password
                Description : This function is used to create the encrypted file
                
                return      : None
            */

             {

                 if (user_name.length() > USER_NAME_LENGTH || password.length() > PASSWORD_PAD_LEN) 
                     {
                         throw new IllegalArgumentException("Error: Invalid Username or Password");
                     }
         
                 // Creating a new director with name same as file name
                 File dir           = new File(file_name);
                 dir.mkdirs();
                 File metadata_file = new File(dir, "0");
                 metadata_file.createNewFile();
         
                 byte[] salt            = secureRandomNumber(16);             
                 String username_padded = Append_Padding(user_name, USER_NAME_LENGTH);         
                 byte[] hashed_pwd      = Generate_Password_Hash(password, salt);         
                 byte[] header          = new byte[username_padded.length() + hashed_pwd.length + salt.length];
                 
                 System.arraycopy(username_padded.getBytes(), 0, header, 0, username_padded.length());
                 System.arraycopy(hashed_pwd, 0, header, username_padded.length(), hashed_pwd.length);
                 System.arraycopy(salt, 0, header, username_padded.length() + hashed_pwd.length, salt.length);
         
                 byte[] file_length = longToBytes(0);         
                 byte[] secret_data = new byte[hashed_pwd.length + file_length.length];
         
                 System.arraycopy(hashed_pwd, 0, secret_data, 0, hashed_pwd.length);
                 System.arraycopy(file_length, 0, secret_data, hashed_pwd.length, file_length.length);
         
                 Write_Metadata_Create(metadata_file, secret_data, password, salt, header);

                 // System.out.println(username_padded.length());
                 // System.out.println(hashed_pwd.length);
                 // System.out.println(salt.length);
                 // System.out.println(hashed_pwd.length);
                 // System.out.println(file_length.length);

                 // System.out.println(header.length);
                 // System.out.println(secret_data.length);                 

             }
      
        public byte[] Convert_To_Metadata_Array(byte[] secret_data, String password, byte[] salt, byte[] header) throws Exception
            /*
                Parameters  : secret_data, password, salt, header
                Description : This function is used to return the metadata block with header + secret data
                
                return      : metadata
            */

            {
                 secret_data                  = Block_Padding(secret_data, SECRET_DATA_LENGTH);
                 byte[] key                   = Generate_Key(Append_Padding(password, PASSWORD_PAD_LEN), salt);
                 byte[] enc_secret_data       = encript_AES(secret_data, key);         
                 byte[] metadata              = new byte[header.length + enc_secret_data.length];

                 System.arraycopy(header, 0, metadata, 0, header.length);
                 System.arraycopy(enc_secret_data, 0, metadata, header.length, enc_secret_data.length);

                 return metadata;
            }

        public void Write_Metadata_Create(File metadata_file, byte[] secret_data, String password, byte[] salt, byte[] header) throws Exception
             /*
                Parameters  : metadata, metadata_file
                Description : This function is used to create the metadata block of the file
                
                return      : None
            */

            {    byte[] metadata                  = Convert_To_Metadata_Array(secret_data, password, salt, header);
                 byte[] hmac                      = Generate_HMAC(metadata);
                 FileOutputStream metadata_output = new FileOutputStream(metadata_file);             
                 byte[] metadata_and_hmac         = new byte[metadata.length +"\n".getBytes().length+ hmac.length];

                 System.arraycopy(metadata, 0, metadata_and_hmac, 0, metadata.length);
                 System.arraycopy("\n".getBytes(), 0, metadata_and_hmac, metadata.length, "\n".length());
                 System.arraycopy(hmac, 0, metadata_and_hmac, metadata.length+"\n".length(), hmac.length);
         
         
                 byte[] padding = Padding_Algorithm(metadata_and_hmac, 1024);
                 metadata_output.write(padding);
                 metadata_output.close();
            }
     
        public boolean Validate_HMAC(byte[] metadata, File file_handle) throws Exception   
            /*
                Parameters  : metadata, file_handle
                Description : This function is used to update the metadata content of the file
                
                return      : True  - If HMAC is same
                              False - Otherwise
            */ 
             {                 
                 if (metadata.length != 1024) 
                     {
                         throw new Exception("Corrputed File Length : Metadata Block");
                     }

                 byte[] metadata_bytes = new byte[METADATA_DATA_LENGTH];
                 byte[] hmac           = new byte[HMAC_SIZE];
                 
                 FileInputStream metadata_handle = new FileInputStream(file_handle);
                 metadata_handle.read(metadata_bytes);
                 metadata_handle.skip(1);
                 metadata_handle.read(hmac);
                 metadata_handle.close();

                 byte[] metadata_hmac = Generate_HMAC(metadata_bytes);
                 boolean result       = Arrays.equals(hmac, metadata_hmac);
                 
                 return result;
             }
          
        @Override
        public String findUser(String file_name) throws Exception 
            /*
                Parameters  : file_name
                Description : This function is used to return the username of the file
                
                return      : user_name
            */
             {

                 // Creating file objects for the file and its metadata
                 File file                                = new File(file_name);
                 File meta                                = new File(file, "0");
                 FileInputStream metadata_fileinputstream = new FileInputStream(meta);        
                 byte[] metadata                          = metadata_fileinputstream.readAllBytes();
         
                 if (!Validate_HMAC(metadata, meta)) 
                     {
                         throw new Exception("Error: Metadata File Has Been Modified!");
                     }
         
                 metadata_fileinputstream.close();
         
                 byte[] user_name_bytes = Arrays.copyOfRange(metadata, 0, USER_NAME_LENGTH);
                 String user_name       = new String(user_name_bytes).trim();
         

                 return user_name;
             }             
     
        public boolean Validate_Password(byte[] metadata, String password) throws Exception 
             /*
                Parameters  : metadata, password
                Description : This function is used to authenticate the password
                
                return      : True  - if passwords match
                              False - Otherwise
            */
             {
                 byte[] salt                  = Extract_Salt(metadata);
                 byte[] enc_secret_data       = Arrays.copyOfRange(metadata, HEADER_SIZE, METADATA_DATA_LENGTH);
                 byte[] expected_hash         = Generate_Password_Hash(password, salt);
                 byte[] key                   = Generate_Key(Append_Padding(password, PASSWORD_PAD_LEN), salt);
                 byte[] dec_secret_data       = decript_AES(enc_secret_data, key);
                 byte[] actual_hash           = Arrays.copyOfRange(dec_secret_data, 0, PASSWORD_LENGTH);
                 boolean result               = Arrays.equals(actual_hash, expected_hash);

                 
                 return result; 
         
             }
     
        @Override
        public int length(String file_name, String password) throws Exception 
             /*
                Parameters  : file_name, password
                Description : This function is used to return the length of the file
                
                return      : file_length
            */
             {
         
                 File dir           = new File(file_name);
                 File metadata_file = new File(dir, "0");
                 byte[] metadata    = Fetch_MetaData(file_name);
         

                 Check_Password(metadata, password);

                 if (!Validate_HMAC(metadata, metadata_file)) 
                     {
                         throw new Exception("Error: Metadata File Has Been Modified!");
                     }                            
         
                 byte[] salt            = Extract_Salt(metadata);
                 byte[] key             = Generate_Key(Append_Padding(password, PASSWORD_PAD_LEN), salt);
                 byte[] enc_secret_data = Arrays.copyOfRange(metadata, HEADER_SIZE, METADATA_DATA_LENGTH);
                 byte[] dec_secret_data = decript_AES(enc_secret_data, key);
                 byte[] file_len_byte   = Arrays.copyOfRange(dec_secret_data, PASSWORD_LENGTH, dec_secret_data.length);
                 long file_length       = bytesToLong(file_len_byte);
         
                 return (int) file_length;
         
             }

        public byte[] Extract_FileData(int Initial_Block, int Final_Block, File file_handle, byte[] salt, int start_pos, int len, String password) throws Exception
             /*
                Parameters  : Initial_Block, Final_Block, file_handle, salt, start_pos, len, password
                Description : This function is used to return the content of the file blockwise and return the bytes array.
                
                return      : file_content_bytes
            */

            {
                String data       = "";
                int last_index    = salt.length-1;

                 for (int i = Initial_Block + 1; i <= Final_Block + 1; i++) 
                     {
                         byte[] encrypted_text       = read_from_file(new File(file_handle, Integer.toString(i)));
                         salt[last_index]           += 1;
                         byte[] enc_text_unpad       = Arrays.copyOfRange(encrypted_text, 0, SECRET_BLOCK_SIZE);
                         byte[] key                  = Generate_Key(Append_Padding(password, PASSWORD_PAD_LEN), salt);
                         byte[] dec_data             = decript_AES(enc_text_unpad, key);
                         String block_text           = new String(dec_data, StandardCharsets.UTF_8);
                         // String block_text           = byteArray2String(dec_data);

                         if (i == Initial_Block + 1) 
                             {
                                 block_text = block_text.substring(start_pos - Initial_Block * SECRET_BLOCK_SIZE);
                             }

                         if (i == Final_Block + 1) 
                             {
                                 block_text = block_text.substring(0, start_pos + len - Final_Block * SECRET_BLOCK_SIZE);
                             }
                         
                         data += block_text;
                     }
                 
                 byte[] string_bytes = data.getBytes();

                 return string_bytes;
            }

        @Override
        public byte[] read(String file_name, int start_pos, int len, String password) throws Exception
             /*
                Parameters  : file_name, start_pos, length, password
                Description : This function is used to return the content of the file from start position upto length
                
                return      : file content
            */

             {
                 File file_handle  = new File(file_name);        
                 byte[] metadata   = Fetch_MetaData(file_name);

                 Check_Password(metadata, password);
         
                 int file_length  = length(file_name, password);
                 if (start_pos + len > file_length) 
                     {
                         throw new Exception();
                     }
                 
                 int Initial_Block   = (start_pos) / SECRET_BLOCK_SIZE;
                 int Final_Block     = (start_pos + len) / SECRET_BLOCK_SIZE;
                 byte[] salt         = Extract_Salt(metadata);
                 int last_index      = salt.length-1;
                 salt[last_index]   += Initial_Block;
                 byte[] string_bytes = Extract_FileData(Initial_Block, Final_Block, file_handle, salt, start_pos, len, password);

                 return string_bytes;
             }            
        
        public String Extract_Prefix(File file_handle, int i, int starting_position, byte[] key, int Initial_Block) throws Exception
            /*
                Parameters  : file_handle, start_pos, i, key, Initial Block
                Description : This function is used to return the prefix of the block
                
                return      : prefix
            */

            {
                 String prefix               = "";
                 byte[] enc_prefix           = read_from_file(new File(file_handle, Integer.toString(i)));
                 byte[] enc_text_unpad       = Arrays.copyOfRange(enc_prefix, 0, SECRET_BLOCK_SIZE);
                 byte[] dec_prefix           = decript_AES(enc_text_unpad, key);
                 prefix                      = new String(dec_prefix, StandardCharsets.UTF_8);
                 prefix                      = prefix.substring(0, starting_position - Initial_Block * SECRET_BLOCK_SIZE);

                 return prefix;
            }

        public String Extract_Postfix(File file_handle, int i, int starting_position, byte[] key, int Final_Block, int len) throws Exception
            /*
                Parameters  : file_handle, start_pos, i, key, Final Block, length
                Description : This function is used to return the postfix of the block
                
                return      : postfix
            */

            {
                String postfix  = "";
                File end        = new File(file_handle, Integer.toString(i));
                if (end.exists()) 
                    {
                        byte[] enc_postfix              = read_from_file(new File(file_handle, Integer.toString(i)));
                        byte[] enc_postfix_unpad        = Arrays.copyOfRange(enc_postfix, 0, SECRET_BLOCK_SIZE);
                        byte[] dec_postfix              = decript_AES(enc_postfix_unpad, key);
                        postfix                         = new String(dec_postfix, StandardCharsets.UTF_8);

                        if (postfix.length() > starting_position + len - Final_Block * SECRET_BLOCK_SIZE) 
                            {
                                postfix = postfix.substring(starting_position + len - Final_Block * SECRET_BLOCK_SIZE);
                            } 
                        else 
                            {
                                postfix = "";
                            }
                    }

                return postfix;
            }

        public void Write_Blocks(int starting_position, int lastIndex, String password, byte[] salt, int Initial_Block, File file_handle, int i, int Final_Block, int len, String str_content) throws Exception
            /*
                Parameters  : starting_position, lastIndex, password, salt, Initial_Block, file_handle, i, Final_Block, len, str_content
                Description : This function is used to write and save each block to the file
                
                return      : None
            */

            {
                 String prefix    = "";
                 String postfix   = "";
                 int sp           =  (i - 1) * SECRET_BLOCK_SIZE - starting_position;
                 int ep           =  (i) * SECRET_BLOCK_SIZE - starting_position;
                 salt[lastIndex] += 1;
                 byte[] key       = Generate_Key(Append_Padding(password, PASSWORD_PAD_LEN), salt);

                 if (i == Initial_Block + 1 && starting_position != Initial_Block * SECRET_BLOCK_SIZE) 
                     {                                                         
                         prefix   = Extract_Prefix(file_handle, i, starting_position, key, Initial_Block);
                         sp       = Math.max(sp, 0);                             
                     }
     
                 if (i == Final_Block + 1) 
                     {
                        File end = new File(file_handle, Integer.toString(i));
                        if (end.exists()) 
                            {                                
                                postfix = Extract_Postfix(file_handle, i, starting_position, key, Final_Block, len);
                            }
                        ep      = Math.min(ep, len);
                    } 
     
                 String toWrite                 = prefix + str_content.substring(sp, ep) + postfix;
                 byte[] file_content            = toWrite.getBytes();    
                 byte[] en_secret_data_and_hmac = Encrypt_Content(key, file_content);
                 byte[] result                  = Padding_Algorithm(en_secret_data_and_hmac, 1024);

                 save_to_file(result, new File(file_handle, Integer.toString(i))); 
            }

        @Override
        public void write(String file_name, int starting_position, byte[] content, String password) throws Exception 
             /*
                Parameters  : file_name, starting_position, content, password
                Description : This function is used to write and save file
                
                return      : None
            */

             {
                 byte[] metadata    = Fetch_MetaData(file_name);
                 Check_Password(metadata, password);
                 String str_content = new String(content, StandardCharsets.UTF_8);
                 int len            = str_content.length();
                 File file_handle   = new File(file_name);
                 int file_length    = length(file_name, password);
         
                 if (starting_position > file_length || starting_position < 0) 
                     {
                         throw new Exception("Error: Invalid Starting Position");
                     }
                  
                 int Initial_Block = starting_position / SECRET_BLOCK_SIZE;
                 int Final_Block   = (starting_position + len -1) / SECRET_BLOCK_SIZE;         
                 byte[] salt       = Extract_Salt(metadata);       
                 int lastIndex     = salt.length - 1;
                 salt[lastIndex]  += Initial_Block;
                 
                 for (int i = Initial_Block + 1; i <= Final_Block + 1; i++) 
                 {                     
                     Write_Blocks(starting_position, lastIndex, password, salt, Initial_Block, file_handle, i, Final_Block, len, str_content);
                 }
         
                 int current_length  = length(file_name, password);
                 if (starting_position + len > current_length)
                     {
                         updateMetadata(starting_position + len, metadata, file_name);
                     }  
             }

        public byte[] Encrypt_Content(byte[] key, byte[] data) throws Exception
             /*
                Parameters  : key, content
                Description : This function is used to encrypt the data, calculate HMAC for it and append in single byte array
                
                return      : enc_secret_data_hmac byte array
            */

             {
                if(data.length<SECRET_BLOCK_SIZE)
                    {
                        data = Padding_Algorithm(data, SECRET_BLOCK_SIZE);
                    }

                byte[] enc_secret_data         = encript_AES(data, key);
                byte[] hmac                    = Generate_HMAC(enc_secret_data);
                byte[] en_secret_data_and_hmac = new byte[enc_secret_data.length + hmac.length];

                System.arraycopy(enc_secret_data, 0, en_secret_data_and_hmac, 0, enc_secret_data.length);
                System.arraycopy(hmac, 0, en_secret_data_and_hmac, enc_secret_data.length, hmac.length);
                

                return en_secret_data_and_hmac;
             }                     
        
        public boolean Evaluate_Blocks(int Initial_Block,int Final_Block, File dir,byte[] metadata, String password) throws Exception
             /*
                Parameters  : Initial Block, Final Block, dir, metadata and password
                Description : This function is used to check the integrity of the blocks in the file
                
                return      : True  - if block not modified
                              False - Otherwise
            */


            {
                 File meta         = new File(dir, "0");                 
                 Check_Password(metadata, password);
         
                 if (!Validate_HMAC(metadata, meta)) 
                     {
                         return false;
                     }

                for (int i = Initial_Block; i <= Final_Block; i++) 
                     {
                         
                         File file_handle                = new File(dir, Integer.toString(i));
                         FileInputStream fileinputstream = new FileInputStream(file_handle);
                         byte[] block_data               = fileinputstream.readAllBytes();
                         byte[] actual_HMAC              = Arrays.copyOfRange(block_data, SECRET_BLOCK_SIZE, SECRET_BLOCK_SIZE + HMAC_SIZE);
                         byte[] data                     = Arrays.copyOfRange(block_data, 0, SECRET_BLOCK_SIZE);
                         byte[] expected_HMAC            = Generate_HMAC(data);
                         fileinputstream.close();
             
                         if (!Arrays.equals(actual_HMAC, expected_HMAC)) 
                             {
                                 return false;
                             }
                        
                     }
                 

                 return true;
            }

        public byte[] Generate_HMAC(byte[] metadata) throws Exception
            /*
                Parameters  : metadata
                Description : This function is used to Generate HMAC for the given Metadata
                              HMACK[M] = Hash[(K+ ^ opad) || Hash[(K+ ^ ipad)||M)]]
                
                return      : HMAC
            */

            {
                byte[] key          = Arrays.copyOfRange(metadata, USER_NAME_LENGTH + PASSWORD_LENGTH, HEADER_SIZE);
                byte[] keyBytes     = key;
                byte[] messageBytes = metadata;
               
                if (keyBytes.length >= HMAC_SIZE) 
                    {                         
                         keyBytes = hash_SHA256(keyBytes);
                    }

                if (keyBytes.length < HMAC_SIZE) 
                    {
                         keyBytes = Arrays.copyOf(keyBytes, HMAC_SIZE);
                         Arrays.fill(keyBytes, key.length, HMAC_SIZE, (byte) 0);
                    }

                 byte[] ipad = new byte[HMAC_SIZE];
                 byte[] opad = new byte[HMAC_SIZE];

                 // XOR key with inner and outer padding
                for (int i = 0; i < HMAC_SIZE; i++) 
                    {
                        ipad[i] = (byte) (0x36 ^ keyBytes[i]);
                        opad[i] = (byte) (0x5c ^ keyBytes[i]);
                    }

                byte[] innerHashInput = new byte[ipad.length + messageBytes.length];
                System.arraycopy(ipad, 0, innerHashInput, 0, ipad.length);
                System.arraycopy(messageBytes, 0, innerHashInput, ipad.length, messageBytes.length);

                byte[] innerHash = hash_SHA256(innerHashInput);

                byte[] outerHashInput = new byte[opad.length + innerHash.length];
                System.arraycopy(opad, 0, outerHashInput, 0, opad.length);
                System.arraycopy(innerHash, 0, outerHashInput, opad.length, innerHash.length);

                byte[] hmacBytes = hash_SHA256(outerHashInput);


                return hmacBytes;

            }

        @Override
        public boolean check_integrity(String file_name, String password) throws Exception 
              /*
                Parameters  : file_name, password
                Description : This function is used to check the integrity of the file
                
                return      : True  - if file not modified
                              False - Otherwise
            */

             {
                 File dir          = new File(file_name);                 
                 int Initial_Block = 1;
                 byte[] metadata   = Fetch_MetaData(file_name);                
                 int file_length   = length(file_name, password);                 
                 int Final_Block   = (int) (Math.ceil((float)file_length / (float)SECRET_BLOCK_SIZE));
                 boolean result    = Evaluate_Blocks(Initial_Block, Final_Block, dir, metadata, password);


                 return result;
             }             

        public void Cut_Blocks(File file_handle, int Final_Block) throws Exception
            /*
                Parameters  : file_handle, Final_Block
                Description : This function is used to cut the block pointed by file pointer
                
                return      : None
            */

            {
                int file_pointer      = Final_Block + 2;
                File file_handle_new  = new File(file_handle, Integer.toString(file_pointer));
                while (file_handle_new.exists())
                  {
                      file_handle_new.delete();
                      file_pointer++;
                  }
            }

        public void Write_Cut_Data_Update_Metadata(byte[] data, byte[] key, int length, byte[] metadata, String file_name, File file_handle, int Final_Block) throws Exception
            /*
                Parameters  : data, key, length, metadata, file_name, file_handle, Final_Block
                Description : This function is used to write the required blocks, cut the block after it and update Metadata
                
                return      : None
            */

            {
                byte[] enc_secret_data = encript_AES(data, key);
                byte[] hmac                  = Generate_HMAC(enc_secret_data);

                Write_ESD_HMAC(enc_secret_data, hmac, file_handle, Final_Block);

                Cut_Blocks(file_handle, Final_Block);

                updateMetadata(length, metadata, file_name);
            }

        @Override
        public void cut(String file_name, int length, String password) throws Exception 
             /*
                Parameters  : file_name, length, password
                Description : This function is used to read the file data, cut it and write it back
                
                return      : None
            */

             {                 
                  byte[] metadata  = Fetch_MetaData(file_name);
                  File file_handle = new File(file_name);
                  int file_length  = length(file_name, password);
                  
                  Check_Password(metadata, password);
                  
                  if (length > file_length)
                      {
                          throw new Exception("Error: Invalid File Length");
                      }


                  byte[] salt                = Extract_Salt(metadata);
                  int last_index             = salt.length-1;
                  int Block_size             = SECRET_BLOCK_SIZE;
                  int Final_Block            = (length) / Block_size;
                  salt[last_index]          += Final_Block+1;                        
                  byte[] enc_data            = Read_File_Content(file_handle, Final_Block, Block_size);
                  byte[] key                 = Generate_Key(Append_Padding(password, PASSWORD_PAD_LEN), salt);
                  byte[] dec_data            = decript_AES(enc_data, key);
                  String data_text           = new String(dec_data, StandardCharsets.UTF_8);
                  // // String data_text           = byteArray2String(dec_data);
                  data_text                  = data_text.substring(0, length - Final_Block * Block_size);
                  byte[] data                = data_text.getBytes();

                  if(data.length<SECRET_BLOCK_SIZE)
                      {
                          data = Padding_Algorithm(data, SECRET_BLOCK_SIZE);
                      }
          

                  Write_Cut_Data_Update_Metadata(data, key, length, metadata, file_name, file_handle, Final_Block);
              }     
     }
