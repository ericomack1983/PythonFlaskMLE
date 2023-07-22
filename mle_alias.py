#AUTHOR - ERICO RODRIGUES - TEST MLE

#################
#  FLASK SETUP  #
#################
# . fl_env/bin/activate --> Activates Env.
# pip3 list
# pip3 freeze > requirements.txt
###############
#  FLASK RUN  #
###############
# cd $home
# export FLASK_APP="file.py"
# flask run
##############
# GIT UPDATE #
##############
# git add .
# git commit -m 'NEW COMMIT TEXT'
# git push origin main

from flask import Flask
import requests
import logging
import unittest
import base64
import json
import sys
import os
import datetime
import random 
from ast import literal_eval
import os
import sys
import time
from jwcrypto import jwk, jwe
application = Flask(__name__)

@application.route('/')
def hello_world():



    #DEBUG = False
    DEBUG = True

    if DEBUG: print ("Python Path", os.path.dirname(sys.executable))

    print("\n\n")
    print ("####################################################################################")
    print ("######################################### MLE ######################################")
    print ("####################################################################################\n\n")


    # THIS IS EXAMPLE ONLY how will user_id and password look like
    # user_id = '1WM2TT4IHPXC8DQ5I3CH21n1rEBGK-Eyv_oLdzE2VZpDqRn_U'
    # password = '19JRVdej9'

    user_id  = '4NMQKGGZ4ESR7J7AGCTG219yxgs_NHUOaD6NDWj-Bu5xY8xzY'
    password = 'eZD372R7'


    # THIS IS EXAMPLE ONLY how will cert and key look like
    # cert = 'cert.pem'
    # key = 'key_83d11ea6-a22d-4e52-b310-e0558816727d.pem'

    cert = '/Users/ericorodrigues/Documents/Visa/VDkeys/cert.pem'
    key  = '/Users/ericorodrigues/Documents/Visa/VDkeys/key_acbc68d2-3f4f-4d48-800d-30b2254424b3.pem'


        # MLE KEY
        #########
        # THIS IS EXAMPLE ONLY how will myKey_ID, server_cert and private_key look like
        # myKey_ID = '7f591161-6b5f-4136-80b8-2ae8a44ad9eb'
        # server_cert = 'server_cert_7f591161-6b5f-4136-80b8-2ae8a44ad9eb.pem'
        # private_key = 'key_7f591161-6b5f-4136-80b8-2ae8a44ad9eb.pem'

    myKey_ID  = '5fba234e-0703-4888-b8df-ee7c7c7f2875'
    server_cert = '/Users/ericorodrigues/Documents/Visa/VDkeys/MLEserver_cert_5fba234e-0703-4888-b8df-ee7c7c7f2875.cer'
    private_key = '/Users/ericorodrigues/Documents/Visa/VDkeys/MLECertificate_Private_Key_5fba234e-0703-4888-b8df-ee7c7c7f2875.cer'



    if DEBUG: print ("Key_ID", myKey_ID)
    if DEBUG: print ("server_cert", server_cert)
    if DEBUG: print ("private_key", private_key)

    #def encrypt(self, payload):
    def encrypt(payload, server_cert, myKey_ID):
        #config = Configuration()
        payload = json.dumps(payload)
        protected_header = {
                "alg": "RSA-OAEP-256",
                "enc": "A128GCM",
                #"kid": config.api_key['keyId'],
                "kid": myKey_ID,
                "iat": int(round(time.time() * 1000))
            }
        jwetoken = jwe.JWE(payload.encode('utf-8'),
                                #recipient=loadPem('server_cert_7f591161-6b5f-4136-80b8-2ae8a44ad9eb.pem'),
                                recipient=loadPem(server_cert),
                                #recipient=self.loadPem(config.encryption_public_key_path),
                                protected=protected_header)
        encryptedPayload = jwetoken.serialize(compact=True)
        return {"encData": encryptedPayload}   


    #def decrypt(self, encPayload):
    def decrypt(encPayload, private_key):
        print(encPayload);
        if type(encPayload) is str:
            payload = json.loads(encPayload)
        if encPayload.get('encData', True):
            #config = Configuration()
            jwetoken = jwe.JWE()
            #jwetoken.deserialize(payload["encData"], key=self.loadPem(config.decryption_private_key_path))
            #jwetoken.deserialize(encPayload["encData"], key=loadPem('key_7f591161-6b5f-4136-80b8-2ae8a44ad9eb.pem'))
            jwetoken.deserialize(encPayload["encData"], key=loadPem(private_key))
            return jwetoken.payload
        return encPayload

    #def loadPem(self, filePath):
    def loadPem(filePath):
        with open(filePath, "rb") as pemfile:
            return jwk.JWK.from_pem(pemfile.read())

    print("\n\n")
    print ("####################################################################################")
    print ("##################################### END MLE ######################################")
    print ("####################################################################################\n\n")

    # These two lines enable debugging at httplib level (requests->urllib3->http.client)
    # You will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
    # The only thing missing will be the response.body which is not logged.
    try:
        import http.client as http_client
    except ImportError:
        # Python 2
        import httplib as http_client
    http_client.HTTPConnection.debuglevel = 1

    # You must initialize logging, otherwise you'll not see debug output.
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


    print ("START Sample Code for Running a simple transaction using Two-Way (Mutual) SSL")

    headers = { "content-type": "application/json",
                'accept': 'application/json',
                'keyId': myKey_ID
                }

    timeout = 10

    recipientPrimaryAccountNumber = "4957030420210496"


    def datestdtojd (stddate):
        fmt='%Y-%m-%d'
        sdtdate = datetime.datetime.strptime(stddate, fmt)
        sdtdate = sdtdate.timetuple()
        jdate = str(sdtdate.tm_yday)
        if len (jdate) == 1:
            jdate = "00" + jdate
        if len (jdate) == 2:
            jdate = "0" + jdate        
        return(jdate)


    date = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    if DEBUG: print(date)

    systemsTraceAuditNumber = str(random.randint(100000,999999))
    if DEBUG: print ("systemsTraceAuditNumber", systemsTraceAuditNumber)

    def generateRetrievalReferenceNumber (date, systemsTraceAuditNumber):
        
        stddate = date.split('T')[0]
        #print(stddate)
        lastYearDigit = stddate.split('-')[0][-1]
        #print(lastYearDigit)
        jdate = datestdtojd(stddate)
        #print(jdate)
        hour = date.split('T')[1].split(':')[0]
        #print(hour)
        
        retrievalReferenceNumber = lastYearDigit + jdate + hour + systemsTraceAuditNumber
        return(retrievalReferenceNumber)

    retrievalReferenceNumber = generateRetrievalReferenceNumber (date, systemsTraceAuditNumber)
    if DEBUG: print (retrievalReferenceNumber)


    # we will add new variable
    acquiringBin = "408999"

    print("\n\n")
    print ("####################################################################################")
    print ("######################## PUSH (OCT)  Transaction ###################################")
    print ("####################################################################################\n\n")


    url = 'https://sandbox.api.visa.com/visadirect/fundstransfer/v1/pushfundstransactions'

    payload = json.loads('''
    {
    "acquirerCountryCode": "840",
    "acquiringBin": "''' + acquiringBin + '''",
    "amount": "124.05",
    "businessApplicationId": "AA",
    "cardAcceptor": {
    "address": {
    "country": "USA",
    "county": "San Mateo",
    "state": "CA",
    "zipCode": "94404"
    },
    "idCode": "CA-IDCode-77765",
    "name": "Visa Inc. USA-Foster City",
    "terminalId": "TID-9999"
    },
    "localTransactionDateTime": "''' + date + '''",
    "merchantCategoryCode": "6012",
    "pointOfServiceData": {
    "motoECIIndicator": "0",
    "panEntryMode": "90",
    "posConditionCode": "00"
    },
    "recipientName": "rohan",
    "recipientPrimaryAccountNumber": "''' + recipientPrimaryAccountNumber + '''",
    "retrievalReferenceNumber": "''' + retrievalReferenceNumber + '''",
    "senderAccountNumber": "4653459515756154",
    "senderAddress": "901 Metro Center Blvd",
    "senderCity": "Foster City",
    "senderCountryCode": "124",
    "senderName": "Mohammed Qasim",
    "senderReference": "",
    "senderStateCode": "CA",
    "sourceOfFundsCode": "05",
    "systemsTraceAuditNumber": "''' + systemsTraceAuditNumber + '''",
    "transactionCurrencyCode": "USD",
    "settlementServiceIndicator": "9",
    "colombiaNationalServiceData": {
    "countryCodeNationalService": "170",
    "nationalReimbursementFee": "20.00",
    "nationalNetMiscAmountType": "A",
    "nationalNetReimbursementFeeBaseAmount": "20.00",
    "nationalNetMiscAmount": "10.00",
    "addValueTaxReturn": "10.00",
    "taxAmountConsumption": "10.00",
    "addValueTaxAmount": "10.00",
    "costTransactionIndicator": "0",
    "emvTransactionIndicator": "1",
    "nationalChargebackReason": "11"
    }
    }
    ''')

    # we have to encrypt payload
    encryptedPayload = encrypt(payload, server_cert, myKey_ID)

    try:
        response = requests.post(url,
                            cert = (cert, key),
                            headers = headers,
                            auth = (user_id, password),
                            #json = payload,
                            json = encryptedPayload,
                            timeout=timeout
                            #if DEBUG: print (response.text)
    )
    except Exception as e:
        print (e)


    if DEBUG: print (response.json())
    #decryptedPayload = decrypt(r.json())
    decryptedPayload = decrypt(response.json(), private_key)

    #print('hello')
    data = literal_eval(decryptedPayload.decode('utf8'))
    #print('hello1', )
    print("Decrypted payload",data)

    # It might be great to capture transactionIdentifier 
    transactionIdentifier = data['transactionIdentifier']
    if DEBUG: print("transactionIdentifier", transactionIdentifier)

    # Capture X-CORRELATION-ID
    correlation_id = response.headers.get("X-CORRELATION-ID")
    print("correlation_id", correlation_id)

    var1 = str(response.status_code)
    if DEBUG: print("var1", var1)
    var2 = '200'
    msg = " PUSH (OCT) transaction failed"
    assert var1 == var2, msg

    print ("END Sample Code for Running a simple transaction using Two-Way (Mutual) SSL\n\n")

    print("\n\n")
    print ("####################################################################################")
    print ("################################### END ############################################")
    print ("####################################################################################\n\n")

    #return (encryptedPayload,data)
    return {'MLE Encrypted data:': encryptedPayload, 'Data Response': data}
