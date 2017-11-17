
def str_to_bitarray(s):
    # Converts string to a bit array.
    bitArr = list()
    for byte in s:
        bits = bin(byte)[2:] if isinstance(byte, int) else bin(ord(byte))[2:]
        while len(bits) < 8:
            bits = "0"+bits  # Add additional 0's as needed
        for bit in bits:
            bitArr.append(int(bit))
    return(bitArr)

def bitarray_to_str(bitArr):
    # Converts bit array to string
    result = ''
    for i in range(0,len(bitArr),8):
        byte = bitArr[i:i+8]
        s = ''.join([str(b) for b in byte])
        result = result+chr(int(s,2))
    return result

def xor(a, b):
    # xor function - This function is complete
    return [i^j for i,j in zip(a,b)]

def VernamEncrypt(binKey,block):
    # Vernam cipher
    if (len(binKey) != len(block)):
        raise Exception("Key is not same size as block")
    return xor(binKey,block)

def VernamDecrypt(binKey,block):
    # Basically a Vernam cipher.  Note it is
    # exactly the same as encryption.
    return VernamEncrypt(binKey,block)

class BlockChain():

    # Modes
    CBC = 0
    PCBC = 1
    CFB = 2
    
    def __init__(self,keyBit,ivBit,encryptMethod,decryptMethod,mode):
        self.encryptBlk = encryptMethod
        self.decryptBlk = decryptMethod
        self.key = keyBit
        self.iv = ivBit
        self.mode = mode
        # Any other variables you might need

    def encrypt(self,msgList):
        # Returns a list of cipher blocks. These blocks are
        # generated based on the mode. The message may need
        # to be padded if not a multiple of 8 bytes (64 bits).
        cipherBlks = list()
        ivTemp = self.iv
        # Your code here...
        if self.mode == 0:          
            for i in msgList:
                xorValue = xor(ivTemp,i)                            #calling xor funtion
                cipherTextBin = self.encryptBlk(xorValue,self.key)  #calling vernamencrypt function
                cipherBlks.append(cipherTextBin)
                ivTemp = cipherTextBin
        elif self.mode == 1:
            for i in msgList:
                xorValue = xor(ivTemp,i)                            #calling xor funtion
                cipherTextBin = self.encryptBlk(xorValue,self.key)  #calling vernamencrypt function
                cipherBlks.append(cipherTextBin)
                ivTemp = xor(i,cipherTextBin)
        elif self.mode == 2:
            for i in msgList:
                enryptedBlock = self.encryptBlk(ivTemp,self.key)    #calling vernamencrypt function
                cipherTextBin = xor(enryptedBlock,i)
                cipherBlks.append(cipherTextBin)
                ivTemp = cipherTextBin
        else:
            print("Wrong Mode")
        return cipherBlks

    def decrypt(self,cipherBlks):
        # Takes a list of cipher blocks and returns the
        # message. Again, decryption is based on mode.
        msg = ""
        plaintextList = []
        ivTemp1 = self.iv
        # Your code here...
        if self.mode == 0:
            for i in cipherBlks:
                decryptedBlock = self.decryptBlk(i,self.key)    #calling vernamdecrypt function
                plaintextItems = xor(decryptedBlock,ivTemp1)    #calling xor funtion
                plaintextList.append(plaintextItems)
                ivTemp1 = i
        elif self.mode == 1:
            for i in cipherBlks:
                decryptedBlock = self.decryptBlk(i,self.key)    #calling vernamdecrypt function
                plaintextItems = xor(decryptedBlock,ivTemp1)    #calling xor funtion
                plaintextList.append(plaintextItems)
                ivTemp1 = xor(plaintextItems,i)
        elif self.mode == 2:
            for i in cipherBlks:
                decryptedBlock = self.decryptBlk(ivTemp1,self.key)  #calling vernamdecrypt function
                plaintextItems = xor(decryptedBlock,i)              #calling xor funtion
                plaintextList.append(plaintextItems)
                ivTemp1 = i           
        else:
           print("Wrong Mode") 
        msg = bitarray_to_str([x for y in plaintextList for x in y])    #converting binary to string after combing sublists to a single element
        return msg

def padding(msg):
    paddinglen = (8 - (len(msg) % 8))           #getting the last digit number
    msg = msg.ljust((len(msg) + (paddinglen-1)), '0') + str(paddinglen)     #padding zeros and the length of zeros to be removed number at the end
    return msg

def unpad(msg):
    msgLastChar = msg.strip()[-1]               #removing the last char
    msg = msg[:(len(msg)-int(msgLastChar))]
    return(msg)

    
def output(blkChain,msgListBin,text,msg):
    print(text)
    cipherblks = blkChain.encrypt(msgListBin)
    print("Ciphertext Blocks:")
    for blk in cipherblks:
       print(bitarray_to_str(blk))
    print("Decrypted:")
    finalMsg = blkChain.decrypt(cipherblks)
    if len(msg) % 8 != 0:
        finalMsg = unpad(finalMsg)
    print(finalMsg)
    print()

if __name__ == '__main__':
    key = "secret_k"
    iv = "whatever"
    msg = "This is my message.There are many like it but this one is mine."
    padMsg = msg
    if len(msg) % 8 != 0:
        msg = padding(msg)
    msgList = [msg[i:i+8] for i in range(0, len(msg), 8)]
    msgListBin = list()
    for i in msgList:
        msgListBin.append(str_to_bitarray(i))
    binKey = str_to_bitarray(key)
    binIv = str_to_bitarray(iv)
    text = ["******Cipher Block Chaining******","******Propagating Cipher Block Chaining******","******Cipher Feedback******"]
    blkChain = BlockChain(binKey,binIv,VernamEncrypt,VernamDecrypt,BlockChain.CBC)
    output(blkChain,msgListBin,text[0],padMsg)
    blkChain = BlockChain(binKey,binIv,VernamEncrypt,VernamDecrypt,BlockChain.PCBC)
    output(blkChain,msgListBin,text[1],padMsg)
    blkChain = BlockChain(binKey,binIv,VernamEncrypt,VernamDecrypt,BlockChain.CFB)
    output(blkChain,msgListBin,text[2],padMsg)

