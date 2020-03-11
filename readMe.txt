Run on ubuntu (Drag the folder, FT_Assn1_5985171_AaronLimCongKai, to ubuntu environment)

Step 1: drag out all folder in FT_Assn1_5985171_AaronLimCongKai.
Folder to drag out to Desktop:
FileName, Description
Alice, the host
Bob, the client
Gen, the generator

Step 2: Open ubuntu's command prompt.
Gen's command prompt:
cd Desktop 
cd Gen
javac gen.java
java gen

Step 3: Open two new command prompt, 1 for server, 1 for client.
Server's command prompt:
cd Desktop
cd Alice
javac Alice.java
java Alice

Client's command prompt:
cd Desktop
cd Bob
javac Bob.java
java Bob

Step 4 on client's command prompt, enter the correct password to proceed, able to test by entering wrong password.

Step 5: Client will do the initial chat (one way thread), followby by the server, and client chat again. This goes on until client type "exit".