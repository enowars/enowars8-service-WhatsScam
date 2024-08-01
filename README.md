Whatsscam
====================
This service was played as part of the enowars8 tournament. The theme of this years enowars was scamming so my website has a scam like touch with redirects, scammy logos and a scam feeling like atmosphere. 

Whatsscam is an online messenger service that lets you "securely" text with people.
The Service contains vulnerabilities that can leak data. 
Inside the documentation folder a readme is contained that explains the exploits/vulnerabilities and possible fixes.

The main features of this service include a User system this means you can login logout and you have a profile page for your profile.

The second feature is inside the home directory which is a private messaging platform in which you have to use a publickey to text the person that has the corresponding private key.
The List that connects the User to a publickey is inside the userlist so that you can choose a user and copy his publickey to than text him.

The third feature is a groupchat that lets you create join and text inside groups.

The fourth feature is a backup that lets you create a backup of your profile inside the profile page.
The backup works via a token that verifies you than you can see parts of the profile. 

The fifth feature is a adding friend function which works intuitive you can add and reject friends but you can also see part of the profiles of your friends.
This works as a bait for the players and is not a flagstore more details to flagstores inside the ```documentation/README.md```.

The service also contains smaller features like redirects and some other features to include the scam theme besides the main features.

# Running

```bash
git clone git@github.com:enowars/enowars8-service-WhatsScam.git
cd enowars8-service-WhatsScam
cd service
docker-compose up --build
```

The service listens to port: `*:9696`

# Project structure

This is the Project structure the main parts are the service, checker and the documentation.

```js
tree .
.
├── LICENSE
├── README.md
├── checker
│   ├── Dockerfile
│   ├── docker-compose.yaml     
│   ├── requirements.txt        
│   └── src
│       ├── checker.py
│       ├── checker_util_func.py
│       ├── gunicorn.conf.py    
│       └── scam_messages.py
├── documentation
│   ├── README.md
│   ├── fix.py
│   ├── issues
│   │   └── issues.txt      
│   └── key_gen.c
└── service
    ├── Dockerfile
    ├── docker-compose.yml
    ├── entrypoint.sh
    ├── gunicorn.conf.py
    ├── instance
    │   └── database.db
    ├── main.py
    ├── requirements.txt
    └── src
        ├── __init__.py
        ├── aes_encryption.py
        ├── auth.py
        ├── call_c.py
        ├── cleanup.py
        ├── key_gen
        ├── models.py
        ├── rsa_encryption.py
        ├── static
        │   ├── Logo.PNG
        │   ├── index.js
        │   └── style.css
        ├── templates
        │   ├── add_friend.html
        │   ├── backup.html
        │   ├── base.html
        │   ├── flag.html
        │   ├── group_page.html
        │   ├── group_page_unauthorized.html
        │   ├── groups.html
        │   ├── home.html
        │   ├── login.html
        │   ├── profil.html
        │   ├── sign_up.html
        │   └── userlist.html
        └── views.py
```
