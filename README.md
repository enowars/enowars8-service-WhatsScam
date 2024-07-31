Whatsscam
====================
This service was played as part of the enowars8 tournament.

Whatsscam is an online messenger service that lets you "securely" text with people.
The Service contains vulnerabilities that can leak data. 
Inside the documentation folder a readme is contained that explains the exploits/vulnerabilities and possible fixes.

# Running

```bash
git clone git@github.com:enowars/enowars8-service-WhatsScam.git
cd service
docker-compose up
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
