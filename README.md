MTK - My Terminal Keys
======================

Intro
-----
"Terminal" here means death, or at least you terminate your exclusive control over the keys you normally keep strictly secret.

Terminal typically means death, but could mean MIA, incapacity or any other reason you want others to access your secrets in your absence.

### Client Side 

Secrets are only ever encrypted on your devices. No secrets are ever sent to a server.

You decide how to share and save the encrypted data.

The only contact to a server is if you want to set up an optional notification failsafe.

### Trust the People you Love

Define a group of trusted people and a minimum 'quorum' (how many of them have to agree) before your secrets are unlocked.

### Secrets

A secret is any info that you want your trusted quorum to be able to access. Each of these secrets may unlock many more secrets for instance if it is the master passphrase to your password manager. The secret info could be the private key and passphrase to a PGP key, individual bank account credentials, private key (crypto or otherwise)... or any other info at all.

### You Decide

Optionally you can set up an email (or text) alert to yourself (or any number of trusted people) that an attempt to unlock your secrets is underway. 

If there is any reply to such an alert then the decryption will be stopped, and no further attempt can happen within 24 hours.

If no one replies to an alert within the time limit (that you preset), then a final key will be sent to the members of the team. This can then be used to unlock your secrets.

### Your Servers

You can define any number of servers that the mtk program will contact, including ones you have set up.

How it Works
------------
Each person in the team is issued their own private key.

Depending on the quorum you decide, a minmimum nuber of the issued keys need to be used at the same time to unlock the secret you decide.

Only you can resend the 