# TODO 

# Generate Public/Private Key Pairs tied to USER REGISTRATION
  - Ensure that Public Key can be accessed by anyone
  - Ensure that Private Key is a hidden and encrypted file
# Milestone Implementation
  - Milestone 1: The basis for this is implemented with user.py
  - Milestone 2: The basis for this is implemented with verify.py
  - Milestone 3: contacts.py implements contact addition, verification, and listing
  - Milestone 4: network.py implements tracking for users, who is online, and listing them as online to their contatcs
  - Milestone 5: TODO

# Ideas
  - Milestone 5: Proof Of Concept without network sockets firrst then adapt it
  - Milestone 3: Track a User's "Friends" in a JSON string and then allow for communication between users if they are on each other's friend list
    - Friend info is a LOCAL FILE, users do not have access to that information

# General Notes
  - When I talked to Dr. Narain he said we can work off of the assumption that the files are secure-ish
  - We are operating under the idea that user's cannot see eachother's friend list
  - An attacker can see everything except for the private key files
  - Since the Contact/Friend files are local we need to find a way to have users check if they are added on eachother's lists
  - Networks are only broadcasted locally, not through a different instance of the codespace
    - We are going to be implementing Docker Containers to do this
      - I will probs ask him to help me set one up when I next see him -- AJ

# Docker Ideas
  - what im primarily trying to setup is a docker server that will create temporary instances based off of registered users, mapping them to ports so they can communicate. 
  - set it up on a cloud server(?, cloud docker?) so we can just fully test it out with no local restrictions basically with this once it is setup then we can build the file transfer aspect, like we would test transfering actual files between each other and then implement encryption after
  - I am trying to create a way for whenever a user is created/logs in they go into their own temporary container, and then they communicate that way. I am primarily trying to set this up to test user/contact presence then implement file transfer

  - Save keys / .json files to a Volume?
  - How to incorperate multiple containers to set this up?

  - How to tie user registration to automatically add to a users.yaml file
  - How to setup the initial composition.yaml file
  - Dokerfile, what ports need to be exposed

  - network.py works on local machine, how to adapt it for the containers