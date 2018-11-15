from __future__ import print_function
from apiclient.discovery import build
from httplib2 import Http
from oauth2client import file, client, tools
from googleapiclient.errors import HttpError
from pprint import pprint
import json
import base64

class Checker():
    def __init__(self, course, year):
        self.course = course
        self.year = year
        SCOPES = 'https://www.googleapis.com/auth/gmail.readonly'
        #store = file.Storage('dcm_credentials.json')
        store = file.Storage('mswadm_credentials.json')
        creds = store.get()
        if not creds or creds.invalid:
            #flow = client.flow_from_clientsecrets('dcm_data.json', SCOPES)
            flow = client.flow_from_clientsecrets('mswadm_data.json', SCOPES)
            creds = tools.run_flow(flow, store)
        self.service = build('gmail', 'v1', http=creds.authorize(Http()))

    def list_threads_matching_query(self, user_id, query=''):
        try:
            response = self.service.users().threads().list(userId=user_id, q=query).execute()
            threads = []
            if 'threads' in response:
                threads.extend(response['threads'])

            while 'nextPageToken' in response:
                page_token = response['nextPageToken']
                response = self.service.users().threads().list(userId=user_id, q=query,
                                                          pageToken=page_token).execute()
                threads.extend(response['threads'])

            return threads
        except HttpError:
            print('An error occurred')

    def get_thread(self, user_id, thread_id):
        try:
            thread = self.service.users().threads().get(userId=user_id, id=thread_id).execute()
            return thread
        except HttpError:
            print('An error occurred')

    def find_subject(self, headers):
        for e in headers:
            if e["name"] == "Subject":
                return e["value"]

    def find_author(self, headers):
        for e in headers:
            if e["name"] == "From":
                return e["value"]

    def find_to(self, headers):
        for e in headers:
            if e["name"] == "To":
                return e["value"]

    def find_cc(self, headers):
        for e in headers:
            if e["name"] == "CC":
                return e["value"]

    def find_data(self, parts):
        for e in parts:
            if e["mimeType"] == "text/html":
                info = e['headers'][0]['value']
                charset = info[20:-1]
                data = e['body']['data']
                body = base64.urlsafe_b64decode(data).decode(charset, 'ignore')
                return body
            if (e["mimeType"] == "multipart/alternative"):
                info = e['parts'][0]['headers'][0]['value']
                charset = info[21:-1]
                data = e['parts'][0]['body']['data']
                body = base64.urlsafe_b64decode(data).decode(charset, 'ignore')
                return body

    def find_data_charset(self, parts):
        for e in parts:
            if e["mimeType"] == "text/html":
                info = e['headers'][0]['value']
                charset = info[20:-1]
                return charset
            if e["mimeType"] == "multipart/alternative":
                info = e['parts'][0]['headers'][0]['value']
                charset = info[21:-1]
                return charset

    def get_info(self):
        emails = []
        threads_info = self.list_threads_matching_query('me')
        for thread_info in threads_info:
            #print("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            thread = self.get_thread('me', thread_info['id'])
            #print("This is the thread with ID = {}".format(thread['id']))
            for message_info in thread['messages']:
                info = {
                    'email_id' : message_info['id'],
                    'thread_id' : message_info['threadId'],
                    'subject' : self.find_subject(message_info["payload"]["headers"]),
                    'snippet' : message_info['snippet'].encode("latin-1", "ignore"),
                    'data' : self.find_data(message_info['payload']['parts']),
                    'data_charset' : self.find_data_charset(message_info['payload']['parts']),
                    'time_stamp' : message_info["internalDate"],
                    'author' : self.find_author(message_info["payload"]["headers"]),
                    'to' : self.find_to(message_info["payload"]["headers"]),
                    'cc' : self.find_cc(message_info["payload"]["headers"]),
                    'year' : self.year,
                    'course' : self.course
                }

                #print("\t\t Subject = {}".format(message_info["payload"]["headers"][5]["value"]))
                #print("\t\t From = {}".format(message_info["payload"]["headers"][3]["value"]))
                #print("\t\t Subject = {}".format(message_info['subject']))
                #print("\t\t {}".format(message_info))
                jsonb = json.dumps(message_info, sort_keys=True, indent=4)
                #print(jsonb)
                #jsonToPython = json.loads(jsonb)
                #print(jsonToPython)
                #pprint(info)
                emails.append(info)
        return emails


#
# {
#     "historyId": "2297",
#     "id": "165ae11abfc8fa47",
#     "internalDate": "1536223715000",
#     "labelIds": [
#         "CATEGORY_PERSONAL",
#         "INBOX"
#     ],
#     "payload": {
#         "body": {
#             "size": 0
#         },
#         "filename": "",
#         "headers": [
#             {
#                 "name": "Delivered-To",
#                 "value": "piloto.dcm@gmail.com"
#             },
#             {
#                 "name": "Received",
#                 "value": "by 2002:a0c:93b2:0:0:0:0:0 with SMTP id f47-v6csp664635qvf;        Thu, 6 Sep 2018 01:48:38 -0700 (PDT)"
#             },
#             {
#                 "name": "X-Google-Smtp-Source",
#                 "value": "ANB0VdYvp3kfRtsySCjwlKwwVvGqFOJ0lGmN+bBod5zcswOQLhhs3XHPk+7vzg06+uk8kI+d2s+L"
#             },
#             {
#                 "name": "X-Received",
#                 "value": "by 2002:adf:c08c:: with SMTP id d12-v6mr1409941wrf.268.1536223718080;        Thu, 06 Sep 2018 01:48:38 -0700 (PDT)"
#             },
#             {
#                 "name": "ARC-Seal",
#                 "value": "i=1; a=rsa-sha256; t=1536223718; cv=none;        d=google.com; s=arc-20160816;        b=S5FHzyEM5omC9+5SpGrOlLwUrfOB8f/hQa9hnKsqHlzVW8hLoXSj/LZODl8FoTmab5         do96Kevixfl5y4laCqdb0MPeG5lk7oYsGYon+863Bwsdpb5pLpjyvp/ydDuV1oQVX2cR         PyW5KIG0/Kc3pkvyju0fcGwhDtJlDrYqR3jViPGWmS0TJQQwuo4cgV2W39qEOd9u0Qe1         hP5K0shv56wlc7edj5s9Q08zuE6jqgPNnsC9/CdNwmv9ZH1uY65xvKaLgGf3rv5ap+F1         ORLluGSJENpx5NxCql7tYdJTh8fyzAp1yJP+/NyMC90vCXs9z6NcbRhH6cHjkyme53mz         QMbg=="
#             },
#             {
#                 "name": "ARC-Message-Signature",
#                 "value": "i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;        h=mime-version:spamdiagnosticmetadata:spamdiagnosticoutput         :content-language:accept-language:in-reply-to:references:message-id         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;        bh=YqNFrh9FXYayk+72m7Im7VtDTdFpEhB+RFEQgN65CCQ=;        b=nT34NcPvTipJz91GZT3FeQm0asm3E8FB5bMP5f283GY6A9kt3Ip9wsWGBsJOn6kfLs         L+837uqHY27PdesMN8HJ+JrVGRyrkXSDcAhcq65yLkRmoZ28nK5LY4fm+juAJL3lszwI         ZzMttmhdcVjSFcKBHiBjut7VtC8FEE3IfbTRYTumw6mvKJ8bFAjMl5zpK88UNwy9BGYb         AmcZLNnfnw7hfkBln3j/M3H9Nn3xIYOjbWNm9TVOytZ3pYFTBSUWMZpHo331vBCYLrCR         mh6qAI6L+XCnfwgDzXd/IiPAW7qJ0CpJAz1QKPzyXaPFwmOC0VVSBSwYc9lyPxGUe58K         8wOg=="
#             },
#             {
#                 "name": "ARC-Authentication-Results",
#                 "value": "i=1; mx.google.com;       dkim=pass header.i=@unioviedo.onmicrosoft.com header.s=selector1-uniovi-es header.b=S1RDll2G;       spf=pass (google.com: domain of solisjaime@uniovi.es designates 40.107.0.55 as permitted sender) smtp.mailfrom=solisjaime@uniovi.es"
#             },
#             {
#                 "name": "Return-Path",
#                 "value": "<solisjaime@uniovi.es>"
#             },
#             {
#                 "name": "Received",
#                 "value": "from EUR02-AM5-obe.outbound.protection.outlook.com (mail-eopbgr00055.outbound.protection.outlook.com. [40.107.0.55])        by mx.google.com with ESMTPS id a10-v6si3278113wmj.45.2018.09.06.01.48.37        (version=TLS1_2 cipher=ECDHE-RSA-AES128-SHA bits=128/128);        Thu, 06 Sep 2018 01:48:38 -0700 (PDT)"
#             },
#             {
#                 "name": "Received-SPF",
#                 "value": "pass (google.com: domain of solisjaime@uniovi.es designates 40.107.0.55 as permitted sender) client-ip=40.107.0.55;"
#             },
#             {
#                 "name": "Authentication-Results",
#                 "value": "mx.google.com;       dkim=pass header.i=@unioviedo.onmicrosoft.com header.s=selector1-uniovi-es header.b=S1RDll2G;       spf=pass (google.com: domain of solisjaime@uniovi.es designates 40.107.0.55 as permitted sender) smtp.mailfrom=solisjaime@uniovi.es"
#             },
#             {
#                 "name": "DKIM-Signature",
#                 "value": "v=1; a=rsa-sha256; c=relaxed/relaxed; d=unioviedo.onmicrosoft.com; s=selector1-uniovi-es; h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck; bh=YqNFrh9FXYayk+72m7Im7VtDTdFpEhB+RFEQgN65CCQ=; b=S1RDll2G+tWP44V/tlNJo/egaTeTiLD+QYv+ogjyHczhJ2IbRWUamR3QeTAXyDdHOEZIPSOp4CqwyPCSH3S1g4d/h0BGr7MRm5eztB1cq9CErDntA8qcx8iImLbyJUYPYZ8bXGrtS/2IkmqLDS5CFxI2KpBBma+5/SSph1cUPxQ="
#             },
#             {
#                 "name": "Received",
#                 "value": "from AM0PR08MB3188.eurprd08.prod.outlook.com (52.134.93.157) by AM0PR08MB3571.eurprd08.prod.outlook.com (20.177.110.96) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.1080.17; Thu, 6 Sep 2018 08:48:36 +0000"
#             },
#             {
#                 "name": "Received",
#                 "value": "from AM0PR08MB3188.eurprd08.prod.outlook.com ([fe80::b013:6382:2797:68b6]) by AM0PR08MB3188.eurprd08.prod.outlook.com ([fe80::b013:6382:2797:68b6%4]) with mapi id 15.20.1101.019; Thu, 6 Sep 2018 08:48:35 +0000"
#             },
#             {
#                 "name": "From",
#                 "value": "JAIME SOLIS MARTINEZ <solisjaime@uniovi.es>"
#             },
#             {
#                 "name": "To",
#                 "value": "\"EDWARD ROLANDO NU\u00d1EZ VALDEZ\" <nunezedward@uniovi.es>"
#             },
#             {
#                 "name": "CC",
#                 "value": "VICENTE GARCIA DIAZ <garciavicente@uniovi.es>, CRISTIAN GONZALEZ GARCIA <gonzalezcristian@uniovi.es>, JORDAN PASCUAL ESPADA <pascualjordan@uniovi.es>, \"piloto.dcm@gmail.com\" <piloto.dcm@gmail.com>, \"piloto.mswadm@gmail.com\" <piloto.mswadm@gmail.com>"
#             },
#             {
#                 "name": "Subject",
#                 "value": "Re: Distribuci\u00f3n de horas"
#             },
#             {
#                 "name": "Thread-Topic",
#                 "value": "Distribuci\u00f3n de horas"
#             },
#             {
#                 "name": "Thread-Index",
#                 "value": "AQHURDx1v+e+ckcOCU66w1udYfPJwaTf+fPAgAAHzwCAAFUEUoABMddggAAg34CAAUrW1Q=="
#             },
#             {
#                 "name": "Date",
#                 "value": "Thu, 6 Sep 2018 08:48:35 +0000"
#             },
#             {
#                 "name": "Message-ID",
#                 "value": "<E5AB834F-BB78-48DC-98A0-5CDA9730DB61@uniovi.es>"
#             },
#             {
#                 "name": "References",
#                 "value": "<HE1PR04MB0890D22EA934FEAF7257F13CC7030@HE1PR04MB0890.eurprd04.prod.outlook.com> <AM0PR08MB29465B28FD0991CAF6ED660CB9030@AM0PR08MB2946.eurprd08.prod.outlook.com> <CAMd_5XEeZeMQW7MxusLhByenzS03uziHBwHwCB4UXL8gnxa7RQ@mail.gmail.com> <HE1PR04MB08903960F2FF3BD99685204EC7030@HE1PR04MB0890.eurprd04.prod.outlook.com> <AM0PR08MB2946DC4DE0063665640AA5E2B9020@AM0PR08MB2946.eurprd08.prod.outlook.com>,<CAMd_5XFf9MgK3C2ud85DQcJsGVEpBzTS71VOp1KVQ8LbJj0RAg@mail.gmail.com>"
#             },
#             {
#                 "name": "In-Reply-To",
#                 "value": "<CAMd_5XFf9MgK3C2ud85DQcJsGVEpBzTS71VOp1KVQ8LbJj0RAg@mail.gmail.com>"
#             },
#             {
#                 "name": "Accept-Language",
#                 "value": "es-ES, en-US"
#             },
#             {
#                 "name": "Content-Language",
#                 "value": "es-ES"
#             },
#             {
#                 "name": "X-MS-Has-Attach",
#                 "value": ""
#             },
#             {
#                 "name": "X-MS-TNEF-Correlator",
#                 "value": ""
#             },
#             {
#                 "name": "authentication-results",
#                 "value": "spf=none (sender IP is ) smtp.mailfrom=solisjaime@uniovi.es;"
#             },
#             {
#                 "name": "x-originating-ip",
#                 "value": "[83.42.45.233]"
#             },
#             {
#                 "name": "x-ms-publictraffictype",
#                 "value": "Email"
#             },
#             {
#                 "name": "x-microsoft-exchange-diagnostics",
#                 "value": "1;AM0PR08MB3571;6:K7WUBHPNN/zwc1DXB/Ay/WLwbSM26TLCV8nkEG4xvTIRdlzUQSCQKv1r0QwILfCQwxpKJ/s7g/GDd3zbnyg9oZLHFj/+cFgtQ8zIAAw4Tqe9VA8TIrc4d6od5S3lqJmQi0UZfY8IbKbSIqEvduNBd4oFk1NhtH0fNdMspgRrs0mQ05VzNOUVefnreALBcPh1cL+nmreu0FJU18rnYY8gBPmDis3WapPe9t5rkDg8YG7GjFcS2rVlm8k4nB3TQttU0QBEwg1G8rec4KjbcRhhz6UXxGho0VoJNVeNzplbN7Bz0Zwsj/Ob0EDbvQ/L2hOYthYeJdzm+mtOM0F955SNozunYHCEvhIBZCAF64R8iBnSlfAzyjaUAQ41ZPrKHwTJfKTw71LzDdsQ4KrlG6L5EMwBB9NikV014JmYYfzmIwiXSVdOtOgfA55HMsF/ulxAPtBh9Qj4wvvSRkVQfthjXQ==;5:qyV8jsTRr4WFxMfjvSEfGiOjeaimS6ee277GCQ6k69pEcTcfMHDiMS7kleF97P4uau1C8hkIPbgvCcIHgn1vfCj4yJRvZYwEkYK8x8dhY04b4dlZfwcTxqPcJM8MAJowuMIqM70Xt8LpK0zzpGQ2i8qDIrZhv/0HBM4FBdItuaw=;7:EWO/nc3bVTUr7cR3sxMNuzd96KtSMLQ3Ltm0ZJHNiPylSeABKGyhjzf7z90sPIxmRy6cb4vDdR30HkgMHMN1/R4ZZk9gKj8a9xDcJS8j13GsTgoX5aEf4v+CQ29nTnXtq5lRLiqg6/H3uhxgjOPGdaimRjxW7c4ulruZLL5dQcN5Bl3yxV4h4JTtly+rteCmXPUyk1V3pR3tT3uaRGvNL2zRjxnlPlKIBLAHqW6riUwXb3JAuA030S9cvMTF+dRt"
#             },
#             {
#                 "name": "x-ms-exchange-antispam-srfa-diagnostics",
#                 "value": "SOS;SOR;"
#             },
#             {
#                 "name": "x-forefront-antispam-report",
#                 "value": "SFV:SKI;SCL:-1;SFV:NSPM;SFS:(10009020)(39860400002)(136003)(366004)(396003)(376002)(346002)(199004)(189003)(122424002)(486006)(11346002)(476003)(2616005)(446003)(54906003)(33656002)(4326008)(2906002)(450100002)(6116002)(786003)(256004)(37006003)(97736004)(316002)(3846002)(7736002)(83716003)(86362001)(2900100001)(53936002)(99286004)(93886005)(76176011)(8936002)(25786009)(6436002)(6636002)(6512007)(236005)(66066001)(53946003)(81156014)(5250100002)(81166006)(6486002)(229853002)(14454004)(224303003)(6246003)(224313004)(106356001)(26005)(105586002)(54896002)(36756003)(68736007)(102836004)(6506007)(45080400002)(5660300001)(74482002)(39060400002)(53346004)(478600001)(82746002)(6862004);DIR:OUT;SFP:1101;SCL:1;SRVR:AM0PR08MB3571;H:AM0PR08MB3188.eurprd08.prod.outlook.com;FPR:;SPF:None;LANG:es;PTR:InfoNoRecords;A:1;MX:1;"
#             },
#             {
#                 "name": "x-ms-office365-filtering-correlation-id",
#                 "value": "171f6da0-2351-40c3-811e-08d613d58833"
#             },
#             {
#                 "name": "x-microsoft-antispam",
#                 "value": "BCL:0;PCL:0;RULEID:(7020095)(4652040)(8989137)(5600074)(711020)(2017052603328)(7153060)(7193020);SRVR:AM0PR08MB3571;"
#             },
#             {
#                 "name": "x-ms-traffictypediagnostic",
#                 "value": "AM0PR08MB3571:"
#             },
#             {
#                 "name": "x-microsoft-antispam-prvs",
#                 "value": "<AM0PR08MB357151A83436B6E5B5335B94C0010@AM0PR08MB3571.eurprd08.prod.outlook.com>"
#             },
#             {
#                 "name": "x-exchange-antispam-report-test",
#                 "value": "UriScan:(85827821059158)(154628093369822)(130873036417446)(194151415913766);"
#             },
#             {
#                 "name": "x-ms-exchange-senderadcheck",
#                 "value": "1"
#             },
#             {
#                 "name": "x-exchange-antispam-report-cfa-test",
#                 "value": "BCL:0;PCL:0;RULEID:(6040522)(2401047)(8121501046)(5005006)(3002001)(10201501046)(3231311)(944501410)(52105095)(93006095)(93001095)(149027)(150027)(6041310)(20161123564045)(20161123558120)(20161123562045)(20161123560045)(201703131423095)(201702281529075)(201702281528075)(20161123555045)(201703061421075)(201703061406153)(201708071742011)(7699016);SRVR:AM0PR08MB3571;BCL:0;PCL:0;RULEID:;SRVR:AM0PR08MB3571;"
#             },
#             {
#                 "name": "x-forefront-prvs",
#                 "value": "0787459938"
#             },
#             {
#                 "name": "received-spf",
#                 "value": "None (protection.outlook.com: uniovi.es does not designate permitted sender hosts)"
#             },
#             {
#                 "name": "x-microsoft-antispam-message-info",
#                 "value": "SQd7ntZ6ArZjEpOAb0/W8q7jN8Pk4muM8J/vXudy0LJRVR8x1OJvcGz0W01uK0PBDynuQMrBma2681agdYaqXpYEOePSvowHBfw7AozXM87dUMtHtKCeBQzIcJDnL6Q1ABqr17Vi7ntwGNB1H2Tm+z0OM70ixQMTHYE8xbykKcuHeVkYQJwUL/Nyq+/2exs+lpP5uIAQa5wxjDXrXxn1cBWGp4sToUFNUKJUuYQoVDzMkjeT/T4CjjtQuTTA26BOW1PBAh6PhuAOX478CVj1ePH03SsPFDGaUBLicNdKEs0EspHb6A9/CicpqWzDfb5fZbY2rl8FZWhTGpmi5+M+zb0KdJsXcSzMzsxa+toNtR4="
#             },
#             {
#                 "name": "spamdiagnosticoutput",
#                 "value": "1:99"
#             },
#             {
#                 "name": "spamdiagnosticmetadata",
#                 "value": "NSPM"
#             },
#             {
#                 "name": "Content-Type",
#                 "value": "multipart/alternative; boundary=\"_000_E5AB834FBB7848DC98A05CDA9730DB61uniovies_\""
#             },
#             {
#                 "name": "MIME-Version",
#                 "value": "1.0"
#             },
#             {
#                 "name": "X-OriginatorOrg",
#                 "value": "uniovi.es"
#             },
#             {
#                 "name": "X-MS-Exchange-CrossTenant-Network-Message-Id",
#                 "value": "171f6da0-2351-40c3-811e-08d613d58833"
#             },
#             {
#                 "name": "X-MS-Exchange-CrossTenant-originalarrivaltime",
#                 "value": "06 Sep 2018 08:48:35.2292 (UTC)"
#             },
#             {
#                 "name": "X-MS-Exchange-CrossTenant-fromentityheader",
#                 "value": "Hosted"
#             },
#             {
#                 "name": "X-MS-Exchange-CrossTenant-id",
#                 "value": "05ea74a3-92c5-4c31-978a-925c3c799cd0"
#             },
#             {
#                 "name": "X-MS-Exchange-Transport-CrossTenantHeadersStamped",
#                 "value": "AM0PR08MB3571"
#             },
#             {
#                 "name": "X-MS-Exchange-CrossPremises-AuthAs",
#                 "value": "Internal"
#             },
#             {
#                 "name": "X-MS-Exchange-CrossPremises-AuthMechanism",
#                 "value": "04"
#             },
#             {
#                 "name": "X-MS-Exchange-CrossPremises-AuthSource",
#                 "value": "AM0PR08MB3188.eurprd08.prod.outlook.com"
#             },
#             {
#                 "name": "X-MS-Exchange-CrossPremises-TransportTrafficType",
#                 "value": "Email"
#             },
#             {
#                 "name": "X-MS-Exchange-CrossPremises-TransportTrafficSubType",
#                 "value": ""
#             },
#             {
#                 "name": "X-MS-Exchange-CrossPremises-SCL",
#                 "value": "1"
#             },
#             {
#                 "name": "X-MS-Exchange-CrossPremises-messagesource",
#                 "value": "StoreDriver"
#             },
#             {
#                 "name": "X-MS-Exchange-CrossPremises-BCC",
#                 "value": ""
#             },
#             {
#                 "name": "X-MS-Exchange-CrossPremises-originalclientipaddress",
#                 "value": "83.42.45.233"
#             },
#             {
#                 "name": "X-MS-Exchange-CrossPremises-transporttraffictype",
#                 "value": "Email"
#             },
#             {
#                 "name": "X-MS-Exchange-CrossPremises-transporttrafficsubtype",
#                 "value": ""
#             },
#             {
#                 "name": "X-MS-Exchange-CrossPremises-antispam-report",
#                 "value": "SFV:SKI;SCL:-1;"
#             },
#             {
#                 "name": "X-MS-Exchange-CrossPremises-antispam-scancontext",
#                 "value": "DIR:Originating;SFV:NSPM;SKIP:0;"
#             },
#             {
#                 "name": "X-MS-Exchange-CrossPremises-processed-by-journaling",
#                 "value": "Journal Agent"
#             },
#             {
#                 "name": "X-OrganizationHeadersPreserved",
#                 "value": "AM0PR08MB3571.eurprd08.prod.outlook.com"
#             }
#         ],
#         "mimeType": "multipart/alternative",
#         "partId": "",
#         "parts": [
#             {
#                 "body": {
#                     "data": "SG9sYSBhIHRvZG9zLA0KDQpZbyBlc3RveSBkZSB2YWNhY2lvbmVzIGVzdGEgc2VtYW5hIHkgbm8gYW5kbyBwb3IgQXN0dXJpYXMsIGxhIHNlbWFuYSBxdWUgdmllbmUgeWEgZW1waWV6byBhIHRyYWJhamFyIG90cmEgdmV6IHkgbm8gcHVlZG8gaXIgYSBsYSByZXVuacOzbiBlc2EgcXVlIGNvbWVudGFiYWlzIHNpIGZpbmFsbWVudGUgc2Ugb3JnYW5pemEuDQoNCkVuIGN1YW50byBhIGxhcyBjbGFzZXMsIG5vIHRlbmdvIHByZWZlcmVuY2lhIHBvciBkYXIgdW5hIGNvc2EgdSBvdHJhIGFzw60gcXVlIHBvZMOpaXMgYXNpZ25hcm1lIGxvIHF1ZSB2ZcOhaXMuIFNpIHB1ZGllcmEgcXVlZGFyIHRvZG8gYXNpZ25hZG8gYSBsbyBsYXJnbyBkZSBsYSBzZW1hbmEgcXVlIHZpZW5lIHNlcsOtYSBnZW5pYWwgcGFyYSB0ZW5lciBhbGdvIGRlIHRpZW1wbyBwYXJhIHByZXBhcmFyIGxhIGNsYXNlLg0KDQpHcmFjaWFzIHkgdW4gc2FsdWRvLg0KSmFpbWUgU29sw61zIE1hcnTDrW5leg0KDQpFbCA1IHNlcHQgMjAxOCwgYSBsYXMgMTU6MDUsIEVEV0FSRCBST0xBTkRPIE5Vw5FFWiBWQUxERVogPG51bmV6ZWR3YXJkQHVuaW92aS5lczxtYWlsdG86bnVuZXplZHdhcmRAdW5pb3ZpLmVzPj4gZXNjcmliacOzOg0KDQrCoUdyYWNpYXMhDQpCZXN0IHJlZ2FyZHMsDQpEci4gRWR3YXJkIE7DusOxZXoNCg0KDQpFbCBtacOpLiwgNSBzZXB0LiAyMDE4IGEgbGFzIDEzOjEyLCBWSUNFTlRFIEdBUkNJQSBESUFaICg8Z2FyY2lhdmljZW50ZUB1bmlvdmkuZXM8bWFpbHRvOmdhcmNpYXZpY2VudGVAdW5pb3ZpLmVzPj4pIGVzY3JpYmnDszoNCkJ1ZW5hcywNCg0KUGVyZmVjdG8sIGdyYWNpYXMuIEFow60gdmEgdW5hIGFjdHVhbGl6YWNpw7NuOg0KDQpMdWVnbyBlbiBmdW5jacOzbiBkZSBsb3MgYWp1c3RlcyBhbGd1aWVuIHRlbmRyw6EgcXVlIGFqdXN0YXIgaGFjw61hIGFycmliYSAocG9yIGVqZW1wbG8geW8pIHkgb3Ryb3MgaGFjw61hIGFiYWpv4oCmDQoNClByb2Zlc29yZXMNCg0KTW9kZWxhZG8gZGUgU29mdHdhcmUgV2ViIEFkYXB0YWJsZSBEaXJpZ2lkbyBwb3IgTW9kZWxvcw0KDQpEaXNlw7FvIHkgQ29uc3RydWNjacOzbiBkZSBNREENCg0KVG90YWwgIGhvcmFzDQoNCkNsYXNlcyBhIGltcGFydGlyDQoNCkNsYXNlcyBzb2JyZSAxMA0KDQpWaWNlbnRlDQoNCjENCg0KMQ0KDQoyDQoNCjAsNjcNCg0KMCw0NDQ0NDQ0NDQNCg0KSm9yZMOhbg0KDQo0DQoNCjYNCg0KMTANCg0KMywzMw0KDQoyLDIyMjIyMjIyMg0KDQpFZHdhcmQNCg0KMTEsNQ0KDQozLDUNCg0KMTUNCg0KNSwwMA0KDQozLDMzMzMzMzMzMw0KDQpDcmlzdGlhbg0KDQozDQoNCjkNCg0KMTINCg0KNCwwMA0KDQoyLDY2NjY2NjY2Nw0KDQogICBKYWltZQ0KDQozDQoNCjMNCg0KNg0KDQoyLDAwDQoNCjEsMzMzMzMzMzMzDQoNCg0KU1VNQQ0KDQoxNSwwMA0KDQoxMA0KDQoNClNhbHVkb3MhDQoNCg0KRGU6IENyaXN0aWFuIEdvbnrDoWxleiBHYXJjw61hIDxnb256YWxlemdhcmNpYWNyaXN0aWFuQGhvdG1haWwuY29tPG1haWx0bzpnb256YWxlemdhcmNpYWNyaXN0aWFuQGhvdG1haWwuY29tPj4gRW4gbm9tYnJlIGRlIENyaXN0aWFuIEdvbnrDoWxleiBHYXJjw61hDQpFbnZpYWRvIGVsOiBtacOpcmNvbGVzLCA1IGRlIHNlcHRpZW1icmUgZGUgMjAxOCAwOjU3DQpQYXJhOiBFRFdBUkQgUk9MQU5ETyBOVcORRVogVkFMREVaIDxudW5lemVkd2FyZEB1bmlvdmkuZXM8bWFpbHRvOm51bmV6ZWR3YXJkQHVuaW92aS5lcz4-OyBWSUNFTlRFIEdBUkNJQSBESUFaIDxnYXJjaWF2aWNlbnRlQHVuaW92aS5lczxtYWlsdG86Z2FyY2lhdmljZW50ZUB1bmlvdmkuZXM-Pg0KQ0M6IEpBSU1FIFNPTElTIE1BUlRJTkVaIDxzb2xpc2phaW1lQHVuaW92aS5lczxtYWlsdG86c29saXNqYWltZUB1bmlvdmkuZXM-PjsgSk9SREFOIFBBU0NVQUwgRVNQQURBIDxwYXNjdWFsam9yZGFuQHVuaW92aS5lczxtYWlsdG86cGFzY3VhbGpvcmRhbkB1bmlvdmkuZXM-PjsgcGlsb3RvLmRjbUBnbWFpbC5jb208bWFpbHRvOnBpbG90by5kY21AZ21haWwuY29tPjsgcGlsb3RvLm1zd2FkbUBnbWFpbC5jb208bWFpbHRvOnBpbG90by5tc3dhZG1AZ21haWwuY29tPg0KQXN1bnRvOiBSZTogRGlzdHJpYnVjacOzbiBkZSBob3Jhcw0KDQoNCkJ1ZW5hczoNCg0KDQoNCkNyZW8gcXVlIGRlYmVyw61hcyBkZSBhanVzdGFybG8gcGFyYSBxdWUgc2FsZ2FuIDEwIGNsYXNlcyBlbiB0b3RhbCB5IHJlcGFydGlyIGEgcGFydGlyIGRlIGFow60uIFBvciBlamVtcGxvLCBwYXNhbmRvIGxhcyBob3JhcyBhICUgeSBhIHBhcnRpciBkZSBlc2UgJSBzYWNhcyBlbCBuw7ptZXJvIGRlIGTDrWFzIHNvYnJlIGxvcyAxMCBxdWUgaGF5LiBQb3NpYmxlbWVudGUgc2UgdmVyw61hIG1lam9yLCBjcmVvIHlvLg0KDQoNCg0KU2FsdWRvcywNCg0KQ3Jpc3RpYW4NCg0KX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX18NCkRlOiBFZHdhcmQgTnXDsWV6IDxudW5lemVkd2FyZEB1bmlvdmkuZXM8bWFpbHRvOm51bmV6ZWR3YXJkQHVuaW92aS5lcz4-DQpFbnZpYWRvOiBtYXJ0ZXMsIDQgZGUgc2VwdGllbWJyZSBkZSAyMDE4IDEzOjQ3OjU0DQpQYXJhOiBWaWNlbnRlIEdhcmPDrWEgRMOtYXoNCkNjOiBDcmlzdGlhbiBHb256w6FsZXogR2FyY8OtYTsgc29saXNqYWltZUB1bmlvdmkuZXM8bWFpbHRvOnNvbGlzamFpbWVAdW5pb3ZpLmVzPjsgSm9yZMOhbiBQYXNjdWFsIEVzcGFkYTsgcGlsb3RvLmRjbUBnbWFpbC5jb208bWFpbHRvOnBpbG90by5kY21AZ21haWwuY29tPjsgcGlsb3RvLm1zd2FkbUBnbWFpbC5jb208bWFpbHRvOnBpbG90by5tc3dhZG1AZ21haWwuY29tPg0KQXN1bnRvOiBSZTogRGlzdHJpYnVjacOzbiBkZSBob3Jhcw0KDQpIb2xhLA0KDQpDcmVvIHF1ZSBoYWJsYW5kbyBlbiBwZXJzb25hIHBvZGVtb3MgcG9uZXJub3MgbWVqb3IgZGUgYWN1ZXJkby4gUXVlIGxlcyBwYXJlY2Ugc2kgbm9zIHJldW5pbW9zIGVsIHByw7N4aW1vIG1hcnRlcyBhIGxhcyAxMDowMCBwYXJhIGN1YWRyYXJsbyB0b2RvIChwb3IgZGVjaXIgYWxnbykuICBTaSBhbGd1aWVuIG5vIHB1ZWRlIGlyIGEgbGEgcmV1bmnDs24gcXVlIGVudmnDqSBzdSBwcmVmZXJlbmNpYS4NCg0Kwr9RdWUgbGVzIHBhcmVjZT8NCg0KDQpCZXN0IHJlZ2FyZHMsDQpEci4gRWR3YXJkIE7DusOxZXoNCg0KDQpFbCBtYXIuLCA0IHNlcHQuIDIwMTggYSBsYXMgMTM6MjcsIFZJQ0VOVEUgR0FSQ0lBIERJQVogKDxnYXJjaWF2aWNlbnRlQHVuaW92aS5lczxtYWlsdG86Z2FyY2lhdmljZW50ZUB1bmlvdmkuZXM-PikgZXNjcmliacOzOg0KDQpIb2xhLA0KDQoNCg0KR2VuaWFsLCBwdWVzIHZhbW9zIGFycmFuY2FuZG8g8J-Yii4gWW8gbGxlZ28gZWwgZMOtYSAxMCBhIEVzcGHDsWEsIHBvciBzaSBxdWVyw6lpcyBoYWJsYXJsbyBlbiBwZXJzb25hLCBxdWUgaWd1YWwgc2Vyw6EgbcOhcyBzZW5jaWxsbywgcGVybyBjb21vIHF1ZXLDoWlzLCBpZ3VhbCBub3MgYXJyZWdsYW1vcyBwb3IgY29ycmVv4oCmDQoNCg0KDQpPcyBwYXNvIHVuYSBwZXF1ZcOxYSB0YWJsYSBjb24gbGFzIGhvcmFzIHF1ZSBjcmVvIHF1ZSB0ZW5lbW9zIGVuIGxhIGFzaWduYXR1cmEsIHBvciBmYXZvciBkZWNpZG1lIHNpIGVzdMOhIGJpZW4gbyBtYWwgcG9ycXVlIGFzw60gcG9kZW1vcyBkaXN0cmlidWlyIGxhcyBob3JhcyBkZSBsYSBmb3JtYSBtw6FzIGp1c3RhIHBvc2libGUsIHRlbmllbmRvIGVuIGN1ZW50YSBsb3MgdGVtYXMgcXVlIGTDoWJhbW9zIG90cm9zIGHDsW9zOg0KDQoNCg0KSG9yYXMgYXNpZ25hZGFzIHBhcmEgbGFzIGFzaWduYXR1cmFzIGRlIE1ERQ0KDQoNClByb2Zlc29yZXMNCg0KDQpNb2RlbGFkbyBkZSBTb2Z0d2FyZSBXZWIgQWRhcHRhYmxlIERpcmlnaWRvIHBvciBNb2RlbG9zDQoNCg0KRGlzZcOxbyB5IENvbnN0cnVjY2nDs24gZGUgTURBDQoNCg0KVG90YWwgIGhvcmFzDQoNCg0KQ2xhc2VzIGEgaW1wYXJ0aXINCg0KDQpWaWNlbnRlDQoNCg0KMQ0KDQoNCjENCg0KDQoyDQoNCg0KMCw2Nw0KDQoNCkpvcmTDoW4NCg0KDQo0DQoNCg0KNg0KDQoNCjEwDQoNCg0KMywzMw0KDQoNCkVkd2FyZA0KDQoNCjExLDUNCg0KDQozLDUNCg0KDQoxNQ0KDQoNCjUsMDANCg0KDQpDcmlzdGlhbg0KDQoNCjMNCg0KDQo5DQoNCg0KMTINCg0KDQo0LDAwDQoNCg0KSmFpbWUNCg0KDQozDQoNCg0KMw0KDQoNCjYNCg0KDQoyLDAwDQoNCg0KDQoNCkRlIHRvZGFzIGZvcm1hcywgY3JlbyBxdWUgbGFzIGhvcmFzIGVuIGNhZGEgdW5hIGRlIGxhcyBhc2lnbmF0dXJhcyBwb3Igc2VwYXJhZG8gbm8gaW1wb3J0YW4gbXVjaG87IGxvIG3DoXMgaW1wb3J0YW50ZSBlcyBlbCB0b3RhbCBkZSBob3JhcyBwb3JxdWUgYXPDrSBub3MgcG9kZW1vcyBjb29yZGluYWRvciB5IHJlcGFydGlyIGVudHJlIGxhcyBkb3MsIHF1ZSB2YW4gYSBkYXJzZSBsYSBtaXNtYSBzZW1hbmEgKGRlbCAyNCBhbCAyOCBkZSBzZXB0aWVtYnJlKS4NCg0KDQoNClNpIGFsZ3VpZW4gdGllbmUgYWxndW5hIHN1Z2VyZW5jaWEsIGlkZWEsIG8gcXVpZXJlIGRhciBhbGdvIGVuIGNvbmNyZXRvLCBxdWUgbG8gZGlnYSB0YW1iacOpbiwgcXVlIGFzw60gc2Vyw6EgbcOhcyBmw6FjaWwgZWwgcmVwYXJ0byA6LSkNCg0KDQoNClJlY29yZGFkIHBvbmVyIGVuIGNvcGlhIHRhbWJpw6luIGxhcyBkaXJlY2Npb25lcyDigJxwaWxvdG_igJ0uDQoNCg0KDQpWYW1vcyBoYWJsYW5kb-KApg0KDQoNCg0KVW4gc2FsdWRvLCBncmFjaWFzIQ0KDQpWaWNlbnRlDQoNCg0KDQpEZTogQ3Jpc3RpYW4gR29uesOhbGV6IEdhcmPDrWEgPGdvbnphbGV6Z2FyY2lhY3Jpc3RpYW5AaG90bWFpbC5jb208bWFpbHRvOmdvbnphbGV6Z2FyY2lhY3Jpc3RpYW5AaG90bWFpbC5jb20-PiBFbiBub21icmUgZGUgQ3Jpc3RpYW4gR29uesOhbGV6IEdhcmPDrWENCkVudmlhZG8gZWw6IG1hcnRlcywgNCBkZSBzZXB0aWVtYnJlIGRlIDIwMTggMTg6NDcNClBhcmE6IFZJQ0VOVEUgR0FSQ0lBIERJQVogPGdhcmNpYXZpY2VudGVAdW5pb3ZpLmVzPG1haWx0bzpnYXJjaWF2aWNlbnRlQHVuaW92aS5lcz4-OyBFRFdBUkQgUk9MQU5ETyBOVcORRVogVkFMREVaIDxudW5lemVkd2FyZEB1bmlvdmkuZXM8bWFpbHRvOm51bmV6ZWR3YXJkQHVuaW92aS5lcz4-OyBwaWxvdG8uZGNtQGdtYWlsLmNvbTxtYWlsdG86cGlsb3RvLmRjbUBnbWFpbC5jb20-OyBwaWxvdG8ubXN3YWRtQGdtYWlsLmNvbTxtYWlsdG86cGlsb3RvLm1zd2FkbUBnbWFpbC5jb20-DQpBc3VudG86IERpc3RyaWJ1Y2nDs24gZGUgaG9yYXMNCg0KDQoNCkJ1ZW5hczoNCg0KDQoNCmNvbiBlbCBjb21pZW56byBkZSBjdXJzbyB5IHRyYXRhbmRvIGRlIG9yZ2FuaXphcm1lLCBtZSBndXN0YXLDrWEgc2FiZXIgY3VhbCB2YSBhIHNlciBsYSBkaXN0cmlidWNpw7NuIGRlIGhvcmFzIGRlIGFtYmFzIGFzaWduYXR1cmFzIHBhcmEgYXPDrSBwb2RlciBwbGFuZWFyIGVsIGNhbGVuZGFyaW8gYWNhZMOpbWljbyB5IHByZXBhcmFyIGxhcyBhc2lnbmF0dXJhcyBjb21vIHRvY2EuDQoNCg0KDQpTYWx1ZG9zLA0KQ3Jpc3RpYW4NCg==",
#                     "size": 5500
#                 },
#                 "filename": "",
#                 "headers": [
#                     {
#                         "name": "Content-Type",
#                         "value": "text/plain; charset=\"utf-8\""
#                     },
#                     {
#                         "name": "Content-Transfer-Encoding",
#                         "value": "base64"
#                     }
#                 ],
#                 "mimeType": "text/plain",
#                 "partId": "0"
#             },
#             {
#                 "body": {
#                     "data": "PGh0bWw-DQo8aGVhZD4NCjxtZXRhIGh0dHAtZXF1aXY9IkNvbnRlbnQtVHlwZSIgY29udGVudD0idGV4dC9odG1sOyBjaGFyc2V0PXV0Zi04Ij4NCjwvaGVhZD4NCjxib2R5IGRpcj0iYXV0byI-DQpIb2xhIGEgdG9kb3MsDQo8ZGl2Pjxicj4NCjwvZGl2Pg0KPGRpdj5ZbyBlc3RveSBkZSB2YWNhY2lvbmVzIGVzdGEgc2VtYW5hIHkgbm8gYW5kbyBwb3IgQXN0dXJpYXMsIGxhIHNlbWFuYSBxdWUgdmllbmUgeWEgZW1waWV6byBhIHRyYWJhamFyIG90cmEgdmV6IHkgbm8gcHVlZG8gaXIgYSBsYSByZXVuacOzbiBlc2EgcXVlIGNvbWVudGFiYWlzIHNpIGZpbmFsbWVudGUgc2Ugb3JnYW5pemEuPC9kaXY-DQo8ZGl2Pjxicj4NCjwvZGl2Pg0KPGRpdj5FbiBjdWFudG8gYSBsYXMgY2xhc2VzLCBubyB0ZW5nbyBwcmVmZXJlbmNpYSBwb3IgZGFyIHVuYSBjb3NhIHUgb3RyYSBhc8OtIHF1ZSBwb2TDqWlzIGFzaWduYXJtZSBsbyBxdWUgdmXDoWlzLiBTaSBwdWRpZXJhIHF1ZWRhciB0b2RvIGFzaWduYWRvIGEgbG8gbGFyZ28gZGUgbGEgc2VtYW5hIHF1ZSB2aWVuZSBzZXLDrWEgZ2VuaWFsIHBhcmEgdGVuZXIgYWxnbyBkZSB0aWVtcG8gcGFyYSBwcmVwYXJhciBsYSBjbGFzZS48L2Rpdj4NCjxkaXY-PGJyPg0KPC9kaXY-DQo8ZGl2PkdyYWNpYXMgeSB1biBzYWx1ZG8uPC9kaXY-DQo8ZGl2Pg0KPGRpdiBpZD0iQXBwbGVNYWlsU2lnbmF0dXJlIj5KYWltZSBTb2zDrXMgTWFydMOtbmV6PC9kaXY-DQo8ZGl2Pjxicj4NCkVsIDUgc2VwdCAyMDE4LCBhIGxhcyAxNTowNSwgRURXQVJEIFJPTEFORE8gTlXDkUVaIFZBTERFWiAmbHQ7PGEgaHJlZj0ibWFpbHRvOm51bmV6ZWR3YXJkQHVuaW92aS5lcyI-bnVuZXplZHdhcmRAdW5pb3ZpLmVzPC9hPiZndDsgZXNjcmliacOzOjxicj4NCjxicj4NCjwvZGl2Pg0KPGJsb2NrcXVvdGUgdHlwZT0iY2l0ZSI-DQo8ZGl2Pg0KPGRpdiBkaXI9Imx0ciI-wqFHcmFjaWFzISZuYnNwOzxiciBjbGVhcj0iYWxsIj4NCjxkaXY-DQo8ZGl2IGRpcj0ibHRyIiBjbGFzcz0iZ21haWxfc2lnbmF0dXJlIiBkYXRhLXNtYXJ0bWFpbD0iZ21haWxfc2lnbmF0dXJlIj4NCjxkaXYgZGlyPSJsdHIiPg0KPGRpdj4NCjxkaXYgZGlyPSJsdHIiPg0KPGRpdj4NCjxkaXYgZGlyPSJsdHIiPkJlc3QgcmVnYXJkcyw8YnI-DQpEci4gRWR3YXJkIE7DusOxZXo8YnI-DQo8L2Rpdj4NCjwvZGl2Pg0KPC9kaXY-DQo8L2Rpdj4NCjwvZGl2Pg0KPC9kaXY-DQo8L2Rpdj4NCjxicj4NCjwvZGl2Pg0KPGJyPg0KPGRpdiBjbGFzcz0iZ21haWxfcXVvdGUiPg0KPGRpdiBkaXI9Imx0ciI-RWwgbWnDqS4sIDUgc2VwdC4gMjAxOCBhIGxhcyAxMzoxMiwgVklDRU5URSBHQVJDSUEgRElBWiAoJmx0OzxhIGhyZWY9Im1haWx0bzpnYXJjaWF2aWNlbnRlQHVuaW92aS5lcyI-Z2FyY2lhdmljZW50ZUB1bmlvdmkuZXM8L2E-Jmd0OykgZXNjcmliacOzOjxicj4NCjwvZGl2Pg0KPGJsb2NrcXVvdGUgY2xhc3M9ImdtYWlsX3F1b3RlIiBzdHlsZT0ibWFyZ2luOjAgMCAwIC44ZXg7Ym9yZGVyLWxlZnQ6MXB4ICNjY2Mgc29saWQ7cGFkZGluZy1sZWZ0OjFleCI-DQo8ZGl2IGxhbmc9IkVTIiBsaW5rPSJibHVlIiB2bGluaz0icHVycGxlIj4NCjxkaXYgY2xhc3M9Im1fODAxMTY1NzcwMTY0MTk1NjI3NldvcmRTZWN0aW9uMSI-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIj48c3Bhbj5CdWVuYXMsPHU-PC91Pjx1PjwvdT48L3NwYW4-PC9wPg0KPHAgY2xhc3M9Ik1zb05vcm1hbCI-PHNwYW4-PHU-PC91PiZuYnNwOzx1PjwvdT48L3NwYW4-PC9wPg0KPHAgY2xhc3M9Ik1zb05vcm1hbCI-PHNwYW4-UGVyZmVjdG8sIGdyYWNpYXMuIEFow60gdmEgdW5hIGFjdHVhbGl6YWNpw7NuOjx1PjwvdT48dT48L3U-PC9zcGFuPjwvcD4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiPjxzcGFuPjx1PjwvdT4mbmJzcDs8dT48L3U-PC9zcGFuPjwvcD4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiPjxzcGFuPkx1ZWdvIGVuIGZ1bmNpw7NuIGRlIGxvcyBhanVzdGVzIGFsZ3VpZW4gdGVuZHLDoSBxdWUgYWp1c3RhciBoYWPDrWEgYXJyaWJhIChwb3IgZWplbXBsbyB5bykgeSBvdHJvcyBoYWPDrWEgYWJham_igKY8dT48L3U-PHU-PC91Pjwvc3Bhbj48L3A-DQo8dGFibGUgY2xhc3M9Im1fODAxMTY1NzcwMTY0MTk1NjI3Nk1zb05vcm1hbFRhYmxlIiBib3JkZXI9IjAiIGNlbGxzcGFjaW5nPSIwIiBjZWxscGFkZGluZz0iMCIgd2lkdGg9Ijk1MSIgc3R5bGU9IndpZHRoOjcxMy4wcHQ7Ym9yZGVyLWNvbGxhcHNlOmNvbGxhcHNlIj4NCjx0Ym9keT4NCjx0ciBzdHlsZT0iaGVpZ2h0OjE0LjVwdCI-DQo8dGQgd2lkdGg9IjgxMyIgbm93cmFwPSIiIGNvbHNwYW49IjUiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6NjEwLjBwdDtwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8L3RkPg0KPHRkIHdpZHRoPSIxMzciIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjEwMy4wcHQ7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPC90ZD4NCjwvdHI-DQo8dHIgc3R5bGU9ImhlaWdodDoxNC41cHQiPg0KPHRkIHdpZHRoPSI3NSIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6NTUuOXB0O2JvcmRlcjpzb2xpZCAjOWJjMmU2IDEuMHB0O2JvcmRlci1yaWdodDpub25lO2JhY2tncm91bmQ6IzViOWJkNTtwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIiBhbGlnbj0iY2VudGVyIiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXIiPjxiPjxzcGFuIHN0eWxlPSJjb2xvcjp3aGl0ZSI-UHJvZmVzb3Jlczx1PjwvdT48dT48L3U-PC9zcGFuPjwvYj48L3A-DQo8L3RkPg0KPHRkIHdpZHRoPSIyMTgiIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjE2My44NXB0O2JvcmRlci10b3A6c29saWQgIzliYzJlNiAxLjBwdDtib3JkZXItbGVmdDpub25lO2JvcmRlci1ib3R0b206c29saWQgIzliYzJlNiAxLjBwdDtib3JkZXItcmlnaHQ6bm9uZTtiYWNrZ3JvdW5kOiM1YjliZDU7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Ik1zb05vcm1hbCIgYWxpZ249ImNlbnRlciIgc3R5bGU9InRleHQtYWxpZ246Y2VudGVyIj48Yj48c3BhbiBzdHlsZT0iY29sb3I6d2hpdGUiPk1vZGVsYWRvIGRlIFNvZnR3YXJlIFdlYiBBZGFwdGFibGUgRGlyaWdpZG8gcG9yIE1vZGVsb3M8dT48L3U-PHU-PC91Pjwvc3Bhbj48L2I-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMjI3IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDo2LjBjbTtib3JkZXItdG9wOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLWxlZnQ6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLXJpZ2h0Om5vbmU7YmFja2dyb3VuZDojNWI5YmQ1O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiIGFsaWduPSJjZW50ZXIiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlciI-PGI-PHNwYW4gc3R5bGU9ImNvbG9yOndoaXRlIj5EaXNlw7FvIHkgQ29uc3RydWNjacOzbiBkZSBNREE8dT48L3U-PHU-PC91Pjwvc3Bhbj48L2I-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMTcwIiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDoxMjcuNTVwdDtib3JkZXItdG9wOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLWxlZnQ6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLXJpZ2h0Om5vbmU7YmFja2dyb3VuZDojNWI5YmQ1O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiIGFsaWduPSJjZW50ZXIiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlciI-PGI-PHNwYW4gc3R5bGU9ImNvbG9yOndoaXRlIj5Ub3RhbCZuYnNwOyBob3Jhczx1PjwvdT48dT48L3U-PC9zcGFuPjwvYj48L3A-DQo8L3RkPg0KPHRkIHdpZHRoPSIxMjMiIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjkyLjZwdDtib3JkZXItdG9wOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLWxlZnQ6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLXJpZ2h0Om5vbmU7YmFja2dyb3VuZDojNWI5YmQ1O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiIGFsaWduPSJjZW50ZXIiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlciI-PGI-PHNwYW4gc3R5bGU9ImNvbG9yOndoaXRlIj5DbGFzZXMgYSBpbXBhcnRpcjx1PjwvdT48dT48L3U-PC9zcGFuPjwvYj48L3A-DQo8L3RkPg0KPHRkIHdpZHRoPSIxMzciIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjEwMy4wcHQ7Ym9yZGVyOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLWxlZnQ6bm9uZTtiYWNrZ3JvdW5kOiM1YjliZDU7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Ik1zb05vcm1hbCIgYWxpZ249ImNlbnRlciIgc3R5bGU9InRleHQtYWxpZ246Y2VudGVyIj48Yj48c3BhbiBzdHlsZT0iY29sb3I6d2hpdGUiPkNsYXNlcyBzb2JyZSAxMDx1PjwvdT48dT48L3U-PC9zcGFuPjwvYj48L3A-DQo8L3RkPg0KPC90cj4NCjx0ciBzdHlsZT0iaGVpZ2h0OjE0LjVwdCI-DQo8dGQgd2lkdGg9Ijc1IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDo1NS45cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0OnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JvcmRlci1yaWdodDpub25lO2JhY2tncm91bmQ6I2RkZWJmNztwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIiBhbGlnbj0iY2VudGVyIiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXIiPjxzcGFuIHN0eWxlPSJjb2xvcjpibGFjayI-VmljZW50ZTx1PjwvdT48dT48L3U-PC9zcGFuPjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjIxOCIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6MTYzLjg1cHQ7Ym9yZGVyOm5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JhY2tncm91bmQ6I2RkZWJmNztwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIiBhbGlnbj0iY2VudGVyIiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXIiPjxzcGFuIHN0eWxlPSJjb2xvcjpibGFjayI-MTx1PjwvdT48dT48L3U-PC9zcGFuPjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjIyNyIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6Ni4wY207Ym9yZGVyOm5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JhY2tncm91bmQ6I2RkZWJmNztwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIiBhbGlnbj0iY2VudGVyIiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXIiPjxzcGFuIHN0eWxlPSJjb2xvcjpibGFjayI-MTx1PjwvdT48dT48L3U-PC9zcGFuPjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjE3MCIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6MTI3LjU1cHQ7Ym9yZGVyOm5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JhY2tncm91bmQ6I2RkZWJmNztwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIiBhbGlnbj0iY2VudGVyIiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXIiPjxzcGFuIHN0eWxlPSJjb2xvcjpibGFjayI-Mjx1PjwvdT48dT48L3U-PC9zcGFuPjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjEyMyIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6OTIuNnB0O2JvcmRlcjpub25lO2JvcmRlci1ib3R0b206c29saWQgIzliYzJlNiAxLjBwdDtiYWNrZ3JvdW5kOiNkZGViZjc7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Ik1zb05vcm1hbCIgYWxpZ249ImNlbnRlciIgc3R5bGU9InRleHQtYWxpZ246Y2VudGVyIj48c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPjAsNjc8dT48L3U-PHU-PC91Pjwvc3Bhbj48L3A-DQo8L3RkPg0KPHRkIHdpZHRoPSIxMzciIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjEwMy4wcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjOWJjMmU2IDEuMHB0O2JhY2tncm91bmQ6I2RkZWJmNztwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIiBhbGlnbj0iY2VudGVyIiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXIiPjxzcGFuIHN0eWxlPSJjb2xvcjpibGFjayI-MCw0NDQ0NDQ0NDQ8dT48L3U-PHU-PC91Pjwvc3Bhbj48L3A-DQo8L3RkPg0KPC90cj4NCjx0ciBzdHlsZT0iaGVpZ2h0OjE0LjVwdCI-DQo8dGQgd2lkdGg9Ijc1IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDo1NS45cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0OnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JvcmRlci1yaWdodDpub25lO3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiIGFsaWduPSJjZW50ZXIiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlciI-PHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj5Kb3Jkw6FuPHU-PC91Pjx1PjwvdT48L3NwYW4-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMjE4IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDoxNjMuODVwdDtib3JkZXI6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Ik1zb05vcm1hbCIgYWxpZ249ImNlbnRlciIgc3R5bGU9InRleHQtYWxpZ246Y2VudGVyIj48c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPjQ8dT48L3U-PHU-PC91Pjwvc3Bhbj48L3A-DQo8L3RkPg0KPHRkIHdpZHRoPSIyMjciIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjYuMGNtO2JvcmRlcjpub25lO2JvcmRlci1ib3R0b206c29saWQgIzliYzJlNiAxLjBwdDtwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIiBhbGlnbj0iY2VudGVyIiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXIiPjxzcGFuIHN0eWxlPSJjb2xvcjpibGFjayI-Njx1PjwvdT48dT48L3U-PC9zcGFuPjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjE3MCIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6MTI3LjU1cHQ7Ym9yZGVyOm5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiIGFsaWduPSJjZW50ZXIiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlciI-PHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj4xMDx1PjwvdT48dT48L3U-PC9zcGFuPjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjEyMyIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6OTIuNnB0O2JvcmRlcjpub25lO2JvcmRlci1ib3R0b206c29saWQgIzliYzJlNiAxLjBwdDtwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIiBhbGlnbj0iY2VudGVyIiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXIiPjxzcGFuIHN0eWxlPSJjb2xvcjpibGFjayI-MywzMzx1PjwvdT48dT48L3U-PC9zcGFuPjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjEzNyIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6MTAzLjBwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICM5YmMyZTYgMS4wcHQ7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Ik1zb05vcm1hbCIgYWxpZ249ImNlbnRlciIgc3R5bGU9InRleHQtYWxpZ246Y2VudGVyIj48c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPjIsMjIyMjIyMjIyPHU-PC91Pjx1PjwvdT48L3NwYW4-PC9wPg0KPC90ZD4NCjwvdHI-DQo8dHIgc3R5bGU9ImhlaWdodDoxNC41cHQiPg0KPHRkIHdpZHRoPSI3NSIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6NTUuOXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpzb2xpZCAjOWJjMmU2IDEuMHB0O2JvcmRlci1ib3R0b206c29saWQgIzliYzJlNiAxLjBwdDtib3JkZXItcmlnaHQ6bm9uZTtiYWNrZ3JvdW5kOiNkZGViZjc7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Ik1zb05vcm1hbCIgYWxpZ249ImNlbnRlciIgc3R5bGU9InRleHQtYWxpZ246Y2VudGVyIj48c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPkVkd2FyZDx1PjwvdT48dT48L3U-PC9zcGFuPjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjIxOCIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6MTYzLjg1cHQ7Ym9yZGVyOm5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JhY2tncm91bmQ6I2RkZWJmNztwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIiBhbGlnbj0iY2VudGVyIiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXIiPjxzcGFuIHN0eWxlPSJjb2xvcjpibGFjayI-MTEsNTx1PjwvdT48dT48L3U-PC9zcGFuPjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjIyNyIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6Ni4wY207Ym9yZGVyOm5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JhY2tncm91bmQ6I2RkZWJmNztwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIiBhbGlnbj0iY2VudGVyIiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXIiPjxzcGFuIHN0eWxlPSJjb2xvcjpibGFjayI-Myw1PHU-PC91Pjx1PjwvdT48L3NwYW4-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMTcwIiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDoxMjcuNTVwdDtib3JkZXI6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7YmFja2dyb3VuZDojZGRlYmY3O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiIGFsaWduPSJjZW50ZXIiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlciI-PHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj4xNTx1PjwvdT48dT48L3U-PC9zcGFuPjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjEyMyIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6OTIuNnB0O2JvcmRlcjpub25lO2JvcmRlci1ib3R0b206c29saWQgIzliYzJlNiAxLjBwdDtiYWNrZ3JvdW5kOiNkZGViZjc7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Ik1zb05vcm1hbCIgYWxpZ249ImNlbnRlciIgc3R5bGU9InRleHQtYWxpZ246Y2VudGVyIj48c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPjUsMDA8dT48L3U-PHU-PC91Pjwvc3Bhbj48L3A-DQo8L3RkPg0KPHRkIHdpZHRoPSIxMzciIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjEwMy4wcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjOWJjMmU2IDEuMHB0O2JhY2tncm91bmQ6I2RkZWJmNztwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIiBhbGlnbj0iY2VudGVyIiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXIiPjxzcGFuIHN0eWxlPSJjb2xvcjpibGFjayI-MywzMzMzMzMzMzM8dT48L3U-PHU-PC91Pjwvc3Bhbj48L3A-DQo8L3RkPg0KPC90cj4NCjx0ciBzdHlsZT0iaGVpZ2h0OjE0LjVwdCI-DQo8dGQgd2lkdGg9Ijc1IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDo1NS45cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0OnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JvcmRlci1yaWdodDpub25lO3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiIGFsaWduPSJjZW50ZXIiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlciI-PHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj5DcmlzdGlhbjx1PjwvdT48dT48L3U-PC9zcGFuPjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjIxOCIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6MTYzLjg1cHQ7Ym9yZGVyOm5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiIGFsaWduPSJjZW50ZXIiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlciI-PHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj4zPHU-PC91Pjx1PjwvdT48L3NwYW4-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMjI3IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDo2LjBjbTtib3JkZXI6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Ik1zb05vcm1hbCIgYWxpZ249ImNlbnRlciIgc3R5bGU9InRleHQtYWxpZ246Y2VudGVyIj48c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPjk8dT48L3U-PHU-PC91Pjwvc3Bhbj48L3A-DQo8L3RkPg0KPHRkIHdpZHRoPSIxNzAiIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjEyNy41NXB0O2JvcmRlcjpub25lO2JvcmRlci1ib3R0b206c29saWQgIzliYzJlNiAxLjBwdDtwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIiBhbGlnbj0iY2VudGVyIiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXIiPjxzcGFuIHN0eWxlPSJjb2xvcjpibGFjayI-MTI8dT48L3U-PHU-PC91Pjwvc3Bhbj48L3A-DQo8L3RkPg0KPHRkIHdpZHRoPSIxMjMiIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjkyLjZwdDtib3JkZXI6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Ik1zb05vcm1hbCIgYWxpZ249ImNlbnRlciIgc3R5bGU9InRleHQtYWxpZ246Y2VudGVyIj48c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPjQsMDA8dT48L3U-PHU-PC91Pjwvc3Bhbj48L3A-DQo8L3RkPg0KPHRkIHdpZHRoPSIxMzciIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjEwMy4wcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjOWJjMmU2IDEuMHB0O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiIGFsaWduPSJjZW50ZXIiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlciI-PHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj4yLDY2NjY2NjY2Nzx1PjwvdT48dT48L3U-PC9zcGFuPjwvcD4NCjwvdGQ-DQo8L3RyPg0KPHRyIHN0eWxlPSJoZWlnaHQ6MTQuNXB0Ij4NCjx0ZCB3aWR0aD0iNzUiIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjU1LjlwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6c29saWQgIzliYzJlNiAxLjBwdDtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLXJpZ2h0Om5vbmU7YmFja2dyb3VuZDojZGRlYmY3O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiPjxzcGFuIHN0eWxlPSJjb2xvcjpibGFjayI-Jm5ic3A7Jm5ic3A7IEphaW1lPHU-PC91Pjx1PjwvdT48L3NwYW4-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMjE4IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDoxNjMuODVwdDtib3JkZXI6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7YmFja2dyb3VuZDojZGRlYmY3O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiIGFsaWduPSJjZW50ZXIiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlciI-PHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj4zPHU-PC91Pjx1PjwvdT48L3NwYW4-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMjI3IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDo2LjBjbTtib3JkZXI6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7YmFja2dyb3VuZDojZGRlYmY3O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiIGFsaWduPSJjZW50ZXIiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlciI-PHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj4zPHU-PC91Pjx1PjwvdT48L3NwYW4-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMTcwIiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDoxMjcuNTVwdDtib3JkZXI6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7YmFja2dyb3VuZDojZGRlYmY3O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiIGFsaWduPSJjZW50ZXIiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlciI-PHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj42PHU-PC91Pjx1PjwvdT48L3NwYW4-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMTIzIiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDo5Mi42cHQ7Ym9yZGVyOm5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JhY2tncm91bmQ6I2RkZWJmNztwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIiBhbGlnbj0iY2VudGVyIiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXIiPjxzcGFuIHN0eWxlPSJjb2xvcjpibGFjayI-MiwwMDx1PjwvdT48dT48L3U-PC9zcGFuPjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjEzNyIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6MTAzLjBwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICM5YmMyZTYgMS4wcHQ7YmFja2dyb3VuZDojZGRlYmY3O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiIGFsaWduPSJjZW50ZXIiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlciI-PHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj4xLDMzMzMzMzMzMzx1PjwvdT48dT48L3U-PC9zcGFuPjwvcD4NCjwvdGQ-DQo8L3RyPg0KPHRyIHN0eWxlPSJoZWlnaHQ6MTQuNXB0Ij4NCjx0ZCB3aWR0aD0iNzUiIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjU1LjlwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6c29saWQgIzliYzJlNiAxLjBwdDtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLXJpZ2h0Om5vbmU7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMjE4IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDoxNjMuODVwdDtib3JkZXI6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMjI3IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDo2LjBjbTtib3JkZXI6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMTcwIiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDoxMjcuNTVwdDtib3JkZXI6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Ik1zb05vcm1hbCI-PGI-PHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj5TVU1BPHU-PC91Pjx1PjwvdT48L3NwYW4-PC9iPjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjEyMyIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6OTIuNnB0O2JvcmRlcjpub25lO2JvcmRlci1ib3R0b206c29saWQgIzliYzJlNiAxLjBwdDtwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIiBhbGlnbj0icmlnaHQiIHN0eWxlPSJ0ZXh0LWFsaWduOnJpZ2h0Ij48Yj48c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPjE1LDAwPHU-PC91Pjx1PjwvdT48L3NwYW4-PC9iPjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjEzNyIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6MTAzLjBwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICM5YmMyZTYgMS4wcHQ7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Ik1zb05vcm1hbCIgYWxpZ249InJpZ2h0IiBzdHlsZT0idGV4dC1hbGlnbjpyaWdodCI-PGI-PHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj4xMDx1PjwvdT48dT48L3U-PC9zcGFuPjwvYj48L3A-DQo8L3RkPg0KPC90cj4NCjwvdGJvZHk-DQo8L3RhYmxlPg0KPHAgY2xhc3M9Ik1zb05vcm1hbCI-PHNwYW4-PHU-PC91PiZuYnNwOzx1PjwvdT48L3NwYW4-PC9wPg0KPHAgY2xhc3M9Ik1zb05vcm1hbCI-PHNwYW4-U2FsdWRvcyE8dT48L3U-PHU-PC91Pjwvc3Bhbj48L3A-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIj48c3Bhbj48dT48L3U-Jm5ic3A7PHU-PC91Pjwvc3Bhbj48L3A-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIj48c3Bhbj48dT48L3U-Jm5ic3A7PHU-PC91Pjwvc3Bhbj48L3A-DQo8ZGl2Pg0KPGRpdiBzdHlsZT0iYm9yZGVyOm5vbmU7Ym9yZGVyLXRvcDpzb2xpZCAjZTFlMWUxIDEuMHB0O3BhZGRpbmc6My4wcHQgMGNtIDBjbSAwY20iPg0KPHAgY2xhc3M9Ik1zb05vcm1hbCI-PGI-RGU6PC9iPiBDcmlzdGlhbiBHb256w6FsZXogR2FyY8OtYSAmbHQ7PGEgaHJlZj0ibWFpbHRvOmdvbnphbGV6Z2FyY2lhY3Jpc3RpYW5AaG90bWFpbC5jb20iIHRhcmdldD0iX2JsYW5rIj5nb256YWxlemdhcmNpYWNyaXN0aWFuQGhvdG1haWwuY29tPC9hPiZndDsNCjxiPkVuIG5vbWJyZSBkZSA8L2I-Q3Jpc3RpYW4gR29uesOhbGV6IEdhcmPDrWE8YnI-DQo8Yj5FbnZpYWRvIGVsOjwvYj4gbWnDqXJjb2xlcywgNSBkZSBzZXB0aWVtYnJlIGRlIDIwMTggMDo1Nzxicj4NCjxiPlBhcmE6PC9iPiBFRFdBUkQgUk9MQU5ETyBOVcORRVogVkFMREVaICZsdDs8YSBocmVmPSJtYWlsdG86bnVuZXplZHdhcmRAdW5pb3ZpLmVzIiB0YXJnZXQ9Il9ibGFuayI-bnVuZXplZHdhcmRAdW5pb3ZpLmVzPC9hPiZndDs7IFZJQ0VOVEUgR0FSQ0lBIERJQVogJmx0OzxhIGhyZWY9Im1haWx0bzpnYXJjaWF2aWNlbnRlQHVuaW92aS5lcyIgdGFyZ2V0PSJfYmxhbmsiPmdhcmNpYXZpY2VudGVAdW5pb3ZpLmVzPC9hPiZndDs8YnI-DQo8Yj5DQzo8L2I-IEpBSU1FIFNPTElTIE1BUlRJTkVaICZsdDs8YSBocmVmPSJtYWlsdG86c29saXNqYWltZUB1bmlvdmkuZXMiIHRhcmdldD0iX2JsYW5rIj5zb2xpc2phaW1lQHVuaW92aS5lczwvYT4mZ3Q7OyBKT1JEQU4gUEFTQ1VBTCBFU1BBREEgJmx0OzxhIGhyZWY9Im1haWx0bzpwYXNjdWFsam9yZGFuQHVuaW92aS5lcyIgdGFyZ2V0PSJfYmxhbmsiPnBhc2N1YWxqb3JkYW5AdW5pb3ZpLmVzPC9hPiZndDs7DQo8YSBocmVmPSJtYWlsdG86cGlsb3RvLmRjbUBnbWFpbC5jb20iIHRhcmdldD0iX2JsYW5rIj5waWxvdG8uZGNtQGdtYWlsLmNvbTwvYT47IDxhIGhyZWY9Im1haWx0bzpwaWxvdG8ubXN3YWRtQGdtYWlsLmNvbSIgdGFyZ2V0PSJfYmxhbmsiPg0KcGlsb3RvLm1zd2FkbUBnbWFpbC5jb208L2E-PGJyPg0KPGI-QXN1bnRvOjwvYj4gUmU6IERpc3RyaWJ1Y2nDs24gZGUgaG9yYXM8dT48L3U-PHU-PC91PjwvcD4NCjwvZGl2Pg0KPC9kaXY-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIj48dT48L3U-Jm5ic3A7PHU-PC91PjwvcD4NCjxkaXYgaWQ9Im1fODAxMTY1NzcwMTY0MTk1NjI3NmRpdnRhZ2RlZmF1bHR3cmFwcGVyIj4NCjxwPjxzcGFuIHN0eWxlPSJmb250LXNpemU6MTIuMHB0O2NvbG9yOmJsYWNrIj5CdWVuYXM6PHU-PC91Pjx1PjwvdT48L3NwYW4-PC9wPg0KPHA-PHNwYW4gc3R5bGU9ImZvbnQtc2l6ZToxMi4wcHQ7Y29sb3I6YmxhY2siPjx1PjwvdT4mbmJzcDs8dT48L3U-PC9zcGFuPjwvcD4NCjxwPjxzcGFuIHN0eWxlPSJmb250LXNpemU6MTIuMHB0O2NvbG9yOmJsYWNrIj5DcmVvIHF1ZSBkZWJlcsOtYXMgZGUgYWp1c3RhcmxvIHBhcmEgcXVlIHNhbGdhbiAxMCBjbGFzZXMgZW4gdG90YWwgeSByZXBhcnRpciBhIHBhcnRpciBkZSBhaMOtLiBQb3IgZWplbXBsbywgcGFzYW5kbyBsYXMgaG9yYXMgYSAlIHkgYSBwYXJ0aXIgZGUgZXNlICUgc2FjYXMgZWwgbsO6bWVybyBkZSBkw61hcyBzb2JyZSBsb3MgMTAgcXVlIGhheS4gUG9zaWJsZW1lbnRlIHNlDQogdmVyw61hIG1lam9yLCBjcmVvIHlvLjx1PjwvdT48dT48L3U-PC9zcGFuPjwvcD4NCjxwPjxzcGFuIHN0eWxlPSJmb250LXNpemU6MTIuMHB0O2NvbG9yOmJsYWNrIj48dT48L3U-Jm5ic3A7PHU-PC91Pjwvc3Bhbj48L3A-DQo8cD48c3BhbiBzdHlsZT0iZm9udC1zaXplOjEyLjBwdDtjb2xvcjpibGFjayI-U2FsdWRvcyw8dT48L3U-PHU-PC91Pjwvc3Bhbj48L3A-DQo8cD48c3BhbiBzdHlsZT0iZm9udC1zaXplOjEyLjBwdDtjb2xvcjpibGFjayI-Q3Jpc3RpYW48dT48L3U-PHU-PC91Pjwvc3Bhbj48L3A-DQo8L2Rpdj4NCjxkaXYgY2xhc3M9Ik1zb05vcm1hbCIgYWxpZ249ImNlbnRlciIgc3R5bGU9InRleHQtYWxpZ246Y2VudGVyIj4NCjxociBzaXplPSIzIiB3aWR0aD0iOTglIiBhbGlnbj0iY2VudGVyIj4NCjwvZGl2Pg0KPGRpdiBpZD0ibV84MDExNjU3NzAxNjQxOTU2Mjc2ZGl2UnBseUZ3ZE1zZyI-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIj48Yj48c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPkRlOjwvc3Bhbj48L2I-PHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj4gRWR3YXJkIE51w7FleiAmbHQ7PGEgaHJlZj0ibWFpbHRvOm51bmV6ZWR3YXJkQHVuaW92aS5lcyIgdGFyZ2V0PSJfYmxhbmsiPm51bmV6ZWR3YXJkQHVuaW92aS5lczwvYT4mZ3Q7PGJyPg0KPGI-RW52aWFkbzo8L2I-IG1hcnRlcywgNCBkZSBzZXB0aWVtYnJlIGRlIDIwMTggMTM6NDc6NTQ8YnI-DQo8Yj5QYXJhOjwvYj4gVmljZW50ZSBHYXJjw61hIETDrWF6PGJyPg0KPGI-Q2M6PC9iPiBDcmlzdGlhbiBHb256w6FsZXogR2FyY8OtYTsgPGEgaHJlZj0ibWFpbHRvOnNvbGlzamFpbWVAdW5pb3ZpLmVzIiB0YXJnZXQ9Il9ibGFuayI-DQpzb2xpc2phaW1lQHVuaW92aS5lczwvYT47IEpvcmTDoW4gUGFzY3VhbCBFc3BhZGE7IDxhIGhyZWY9Im1haWx0bzpwaWxvdG8uZGNtQGdtYWlsLmNvbSIgdGFyZ2V0PSJfYmxhbmsiPg0KcGlsb3RvLmRjbUBnbWFpbC5jb208L2E-OyA8YSBocmVmPSJtYWlsdG86cGlsb3RvLm1zd2FkbUBnbWFpbC5jb20iIHRhcmdldD0iX2JsYW5rIj4NCnBpbG90by5tc3dhZG1AZ21haWwuY29tPC9hPjxicj4NCjxiPkFzdW50bzo8L2I-IFJlOiBEaXN0cmlidWNpw7NuIGRlIGhvcmFzPC9zcGFuPiA8dT48L3U-PHU-PC91PjwvcD4NCjxkaXY-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIj4mbmJzcDs8dT48L3U-PHU-PC91PjwvcD4NCjwvZGl2Pg0KPC9kaXY-DQo8ZGl2Pg0KPGRpdj4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiPkhvbGEsIDx1PjwvdT48dT48L3U-PC9wPg0KPGRpdj4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiPjx1PjwvdT4mbmJzcDs8dT48L3U-PC9wPg0KPC9kaXY-DQo8ZGl2Pg0KPHAgY2xhc3M9Ik1zb05vcm1hbCI-Q3JlbyBxdWUgaGFibGFuZG8gZW4gcGVyc29uYSBwb2RlbW9zIHBvbmVybm9zIG1lam9yIGRlIGFjdWVyZG8uIFF1ZSBsZXMgcGFyZWNlIHNpIG5vcyByZXVuaW1vcyBlbCBwcsOzeGltbyBtYXJ0ZXMgYSBsYXMgMTA6MDAgcGFyYSBjdWFkcmFybG8gdG9kbyAocG9yIGRlY2lyIGFsZ28pLiZuYnNwOyBTaSBhbGd1aWVuIG5vIHB1ZWRlIGlyIGEgbGEgcmV1bmnDs24gcXVlIGVudmnDqSBzdSBwcmVmZXJlbmNpYS48dT48L3U-PHU-PC91PjwvcD4NCjwvZGl2Pg0KPGRpdj4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiPjx1PjwvdT4mbmJzcDs8dT48L3U-PC9wPg0KPC9kaXY-DQo8ZGl2Pg0KPHAgY2xhc3M9Ik1zb05vcm1hbCI-wr9RdWUgbGVzIHBhcmVjZT88dT48L3U-PHU-PC91PjwvcD4NCjwvZGl2Pg0KPGRpdj4NCjxwIGNsYXNzPSJNc29Ob3JtYWwiPjx1PjwvdT4mbmJzcDs8dT48L3U-PC9wPg0KPC9kaXY-DQo8ZGl2Pg0KPHAgY2xhc3M9Ik1zb05vcm1hbCI-PGJyIGNsZWFyPSJhbGwiPg0KPHU-PC91Pjx1PjwvdT48L3A-DQo8ZGl2Pg0KPGRpdj4NCjxkaXY-DQo8ZGl2Pg0KPGRpdj4NCjxkaXY-DQo8ZGl2Pg0KPHAgY2xhc3M9Ik1zb05vcm1hbCI-QmVzdCByZWdhcmRzLDxicj4NCkRyLiBFZHdhcmQgTsO6w7Flejx1PjwvdT48dT48L3U-PC9wPg0KPC9kaXY-DQo8L2Rpdj4NCjwvZGl2Pg0KPC9kaXY-DQo8L2Rpdj4NCjwvZGl2Pg0KPC9kaXY-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIj48dT48L3U-Jm5ic3A7PHU-PC91PjwvcD4NCjwvZGl2Pg0KPC9kaXY-DQo8cCBjbGFzcz0iTXNvTm9ybWFsIj48dT48L3U-Jm5ic3A7PHU-PC91PjwvcD4NCjxkaXY-DQo8ZGl2Pg0KPHAgY2xhc3M9Ik1zb05vcm1hbCI-RWwgbWFyLiwgNCBzZXB0LiAyMDE4IGEgbGFzIDEzOjI3LCBWSUNFTlRFIEdBUkNJQSBESUFaICgmbHQ7PGEgaHJlZj0ibWFpbHRvOmdhcmNpYXZpY2VudGVAdW5pb3ZpLmVzIiB0YXJnZXQ9Il9ibGFuayI-Z2FyY2lhdmljZW50ZUB1bmlvdmkuZXM8L2E-Jmd0OykgZXNjcmliacOzOjx1PjwvdT48dT48L3U-PC9wPg0KPC9kaXY-DQo8YmxvY2txdW90ZSBzdHlsZT0iYm9yZGVyOm5vbmU7Ym9yZGVyLWxlZnQ6c29saWQgI2NjY2NjYyAxLjBwdDtwYWRkaW5nOjBjbSAwY20gMGNtIDYuMHB0O21hcmdpbi1sZWZ0OjQuOHB0O21hcmdpbi1yaWdodDowY20iPg0KPGRpdj4NCjxkaXY-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCI-SG9sYSw8dT48L3U-PHU-PC91PjwvcD4NCjxwIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZ4bXNvbm9ybWFsIj4mbmJzcDs8dT48L3U-PHU-PC91PjwvcD4NCjxwIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZ4bXNvbm9ybWFsIj5HZW5pYWwsIHB1ZXMgdmFtb3MgYXJyYW5jYW5kbyA8c3BhbiBzdHlsZT0iZm9udC1mYW1pbHk6JnF1b3Q7U2Vnb2UgVUkgRW1vamkmcXVvdDssc2Fucy1zZXJpZiI-DQrwn5iKPC9zcGFuPi4gWW8gbGxlZ28gZWwgZMOtYSAxMCBhIEVzcGHDsWEsIHBvciBzaSBxdWVyw6lpcyBoYWJsYXJsbyBlbiBwZXJzb25hLCBxdWUgaWd1YWwgc2Vyw6EgbcOhcyBzZW5jaWxsbywgcGVybyBjb21vIHF1ZXLDoWlzLCBpZ3VhbCBub3MgYXJyZWdsYW1vcyBwb3IgY29ycmVv4oCmPHU-PC91Pjx1PjwvdT48L3A-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCI-Jm5ic3A7PHU-PC91Pjx1PjwvdT48L3A-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCI-T3MgcGFzbyB1bmEgcGVxdWXDsWEgdGFibGEgY29uIGxhcyBob3JhcyBxdWUgY3JlbyBxdWUgdGVuZW1vcyBlbiBsYSBhc2lnbmF0dXJhLCBwb3IgZmF2b3IgZGVjaWRtZSBzaSBlc3TDoSBiaWVuIG8gbWFsIHBvcnF1ZSBhc8OtIHBvZGVtb3MgZGlzdHJpYnVpciBsYXMgaG9yYXMgZGUgbGEgZm9ybWEgbcOhcyBqdXN0YSBwb3NpYmxlLCB0ZW5pZW5kbyBlbiBjdWVudGEgbG9zIHRlbWFzDQogcXVlIGTDoWJhbW9zIG90cm9zIGHDsW9zOjx1PjwvdT48dT48L3U-PC9wPg0KPHAgY2xhc3M9Im1fODAxMTY1NzcwMTY0MTk1NjI3Nnhtc29ub3JtYWwiPiZuYnNwOzx1PjwvdT48dT48L3U-PC9wPg0KPHRhYmxlIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZNc29Ob3JtYWxUYWJsZSIgYm9yZGVyPSIwIiBjZWxsc3BhY2luZz0iMCIgY2VsbHBhZGRpbmc9IjAiIHdpZHRoPSI1ODkiIHN0eWxlPSJ3aWR0aDo0NDEuOXB0O2JvcmRlci1jb2xsYXBzZTpjb2xsYXBzZSI-DQo8dGJvZHk-DQo8dHIgc3R5bGU9ImhlaWdodDoxNC41cHQiPg0KPHRkIHdpZHRoPSI1ODkiIG5vd3JhcD0iIiBjb2xzcGFuPSI1IiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjQ0MS45cHQ7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Im1fODAxMTY1NzcwMTY0MTk1NjI3Nnhtc29ub3JtYWwiIGFsaWduPSJjZW50ZXIiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlciI-DQo8Yj48c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPkhvcmFzIGFzaWduYWRhcyBwYXJhIGxhcyBhc2lnbmF0dXJhcyBkZSBNREU8L3NwYW4-PC9iPjx1PjwvdT48dT48L3U-PC9wPg0KPC90ZD4NCjwvdHI-DQo8dHIgc3R5bGU9ImhlaWdodDoxNC41cHQiPg0KPHRkIHdpZHRoPSI0OSIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6MzcuMDVwdDtib3JkZXI6c29saWQgIzliYzJlNiAxLjBwdDtib3JkZXItcmlnaHQ6bm9uZTtiYWNrZ3JvdW5kOiM1YjliZDU7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Im1fODAxMTY1NzcwMTY0MTk1NjI3Nnhtc29ub3JtYWwiPjxiPjxzcGFuIHN0eWxlPSJjb2xvcjp3aGl0ZSI-UHJvZmVzb3Jlczwvc3Bhbj48L2I-PHU-PC91Pjx1PjwvdT48L3A-DQo8L3RkPg0KPHRkIHdpZHRoPSIyNzEiIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjIwMy41NXB0O2JvcmRlci10b3A6c29saWQgIzliYzJlNiAxLjBwdDtib3JkZXItbGVmdDpub25lO2JvcmRlci1ib3R0b206c29saWQgIzliYzJlNiAxLjBwdDtib3JkZXItcmlnaHQ6bm9uZTtiYWNrZ3JvdW5kOiM1YjliZDU7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Im1fODAxMTY1NzcwMTY0MTk1NjI3Nnhtc29ub3JtYWwiPjxiPjxzcGFuIHN0eWxlPSJjb2xvcjp3aGl0ZSI-TW9kZWxhZG8gZGUgU29mdHdhcmUgV2ViIEFkYXB0YWJsZSBEaXJpZ2lkbyBwb3IgTW9kZWxvczwvc3Bhbj48L2I-PHU-PC91Pjx1PjwvdT48L3A-DQo8L3RkPg0KPHRkIHdpZHRoPSIxMzgiIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjEwMy44cHQ7Ym9yZGVyLXRvcDpzb2xpZCAjOWJjMmU2IDEuMHB0O2JvcmRlci1sZWZ0Om5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JvcmRlci1yaWdodDpub25lO2JhY2tncm91bmQ6IzViOWJkNTtwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCI-PGI-PHNwYW4gc3R5bGU9ImNvbG9yOndoaXRlIj5EaXNlw7FvIHkgQ29uc3RydWNjacOzbiBkZSBNREE8L3NwYW4-PC9iPjx1PjwvdT48dT48L3U-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iNTQiIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjQwLjdwdDtib3JkZXItdG9wOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLWxlZnQ6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLXJpZ2h0Om5vbmU7YmFja2dyb3VuZDojNWI5YmQ1O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZ4bXNvbm9ybWFsIj48Yj48c3BhbiBzdHlsZT0iY29sb3I6d2hpdGUiPlRvdGFsJm5ic3A7IGhvcmFzPC9zcGFuPjwvYj48dT48L3U-PHU-PC91PjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9Ijc2IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDo1Ni44cHQ7Ym9yZGVyOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLWxlZnQ6bm9uZTtiYWNrZ3JvdW5kOiM1YjliZDU7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Im1fODAxMTY1NzcwMTY0MTk1NjI3Nnhtc29ub3JtYWwiPjxiPjxzcGFuIHN0eWxlPSJjb2xvcjp3aGl0ZSI-Q2xhc2VzIGEgaW1wYXJ0aXI8L3NwYW4-PC9iPjx1PjwvdT48dT48L3U-PC9wPg0KPC90ZD4NCjwvdHI-DQo8dHIgc3R5bGU9ImhlaWdodDoxNC41cHQiPg0KPHRkIHdpZHRoPSI0OSIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6MzcuMDVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6c29saWQgIzliYzJlNiAxLjBwdDtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLXJpZ2h0Om5vbmU7YmFja2dyb3VuZDojZGRlYmY3O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZ4bXNvbm9ybWFsIj48c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPlZpY2VudGU8L3NwYW4-PHU-PC91Pjx1PjwvdT48L3A-DQo8L3RkPg0KPHRkIHdpZHRoPSIyNzEiIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjIwMy41NXB0O2JvcmRlcjpub25lO2JvcmRlci1ib3R0b206c29saWQgIzliYzJlNiAxLjBwdDtiYWNrZ3JvdW5kOiNkZGViZjc7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Im1fODAxMTY1NzcwMTY0MTk1NjI3Nnhtc29ub3JtYWwiIGFsaWduPSJyaWdodCIgc3R5bGU9InRleHQtYWxpZ246cmlnaHQiPg0KPHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj4xPC9zcGFuPjx1PjwvdT48dT48L3U-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMTM4IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDoxMDMuOHB0O2JvcmRlcjpub25lO2JvcmRlci1ib3R0b206c29saWQgIzliYzJlNiAxLjBwdDtiYWNrZ3JvdW5kOiNkZGViZjc7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Im1fODAxMTY1NzcwMTY0MTk1NjI3Nnhtc29ub3JtYWwiIGFsaWduPSJyaWdodCIgc3R5bGU9InRleHQtYWxpZ246cmlnaHQiPg0KPHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj4xPC9zcGFuPjx1PjwvdT48dT48L3U-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iNTQiIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjQwLjdwdDtib3JkZXI6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7YmFja2dyb3VuZDojZGRlYmY3O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZ4bXNvbm9ybWFsIiBhbGlnbj0icmlnaHQiIHN0eWxlPSJ0ZXh0LWFsaWduOnJpZ2h0Ij4NCjxzcGFuIHN0eWxlPSJjb2xvcjpibGFjayI-Mjwvc3Bhbj48dT48L3U-PHU-PC91PjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9Ijc2IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDo1Ni44cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjOWJjMmU2IDEuMHB0O2JhY2tncm91bmQ6I2RkZWJmNztwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCIgYWxpZ249InJpZ2h0IiBzdHlsZT0idGV4dC1hbGlnbjpyaWdodCI-DQo8c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPjAsNjc8L3NwYW4-PHU-PC91Pjx1PjwvdT48L3A-DQo8L3RkPg0KPC90cj4NCjx0ciBzdHlsZT0iaGVpZ2h0OjE0LjVwdCI-DQo8dGQgd2lkdGg9IjQ5IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDozNy4wNXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpzb2xpZCAjOWJjMmU2IDEuMHB0O2JvcmRlci1ib3R0b206c29saWQgIzliYzJlNiAxLjBwdDtib3JkZXItcmlnaHQ6bm9uZTtwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCI-PHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj5Kb3Jkw6FuPC9zcGFuPjx1PjwvdT48dT48L3U-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMjcxIiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDoyMDMuNTVwdDtib3JkZXI6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Im1fODAxMTY1NzcwMTY0MTk1NjI3Nnhtc29ub3JtYWwiIGFsaWduPSJyaWdodCIgc3R5bGU9InRleHQtYWxpZ246cmlnaHQiPg0KPHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj40PC9zcGFuPjx1PjwvdT48dT48L3U-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMTM4IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDoxMDMuOHB0O2JvcmRlcjpub25lO2JvcmRlci1ib3R0b206c29saWQgIzliYzJlNiAxLjBwdDtwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCIgYWxpZ249InJpZ2h0IiBzdHlsZT0idGV4dC1hbGlnbjpyaWdodCI-DQo8c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPjY8L3NwYW4-PHU-PC91Pjx1PjwvdT48L3A-DQo8L3RkPg0KPHRkIHdpZHRoPSI1NCIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6NDAuN3B0O2JvcmRlcjpub25lO2JvcmRlci1ib3R0b206c29saWQgIzliYzJlNiAxLjBwdDtwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCIgYWxpZ249InJpZ2h0IiBzdHlsZT0idGV4dC1hbGlnbjpyaWdodCI-DQo8c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPjEwPC9zcGFuPjx1PjwvdT48dT48L3U-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iNzYiIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjU2LjhwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICM5YmMyZTYgMS4wcHQ7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Im1fODAxMTY1NzcwMTY0MTk1NjI3Nnhtc29ub3JtYWwiIGFsaWduPSJyaWdodCIgc3R5bGU9InRleHQtYWxpZ246cmlnaHQiPg0KPHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj4zLDMzPC9zcGFuPjx1PjwvdT48dT48L3U-PC9wPg0KPC90ZD4NCjwvdHI-DQo8dHIgc3R5bGU9ImhlaWdodDoxNC41cHQiPg0KPHRkIHdpZHRoPSI0OSIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6MzcuMDVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6c29saWQgIzliYzJlNiAxLjBwdDtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLXJpZ2h0Om5vbmU7YmFja2dyb3VuZDojZGRlYmY3O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZ4bXNvbm9ybWFsIj48c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPkVkd2FyZDwvc3Bhbj48dT48L3U-PHU-PC91PjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjI3MSIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6MjAzLjU1cHQ7Ym9yZGVyOm5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JhY2tncm91bmQ6I2RkZWJmNztwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCIgYWxpZ249InJpZ2h0IiBzdHlsZT0idGV4dC1hbGlnbjpyaWdodCI-DQo8c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPjExLDU8L3NwYW4-PHU-PC91Pjx1PjwvdT48L3A-DQo8L3RkPg0KPHRkIHdpZHRoPSIxMzgiIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjEwMy44cHQ7Ym9yZGVyOm5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JhY2tncm91bmQ6I2RkZWJmNztwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCIgYWxpZ249InJpZ2h0IiBzdHlsZT0idGV4dC1hbGlnbjpyaWdodCI-DQo8c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPjMsNTwvc3Bhbj48dT48L3U-PHU-PC91PjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjU0IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDo0MC43cHQ7Ym9yZGVyOm5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JhY2tncm91bmQ6I2RkZWJmNztwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCIgYWxpZ249InJpZ2h0IiBzdHlsZT0idGV4dC1hbGlnbjpyaWdodCI-DQo8c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPjE1PC9zcGFuPjx1PjwvdT48dT48L3U-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iNzYiIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjU2LjhwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICM5YmMyZTYgMS4wcHQ7YmFja2dyb3VuZDojZGRlYmY3O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZ4bXNvbm9ybWFsIiBhbGlnbj0icmlnaHQiIHN0eWxlPSJ0ZXh0LWFsaWduOnJpZ2h0Ij4NCjxzcGFuIHN0eWxlPSJjb2xvcjpibGFjayI-NSwwMDwvc3Bhbj48dT48L3U-PHU-PC91PjwvcD4NCjwvdGQ-DQo8L3RyPg0KPHRyIHN0eWxlPSJoZWlnaHQ6MTQuNXB0Ij4NCjx0ZCB3aWR0aD0iNDkiIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjM3LjA1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0OnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JvcmRlci1yaWdodDpub25lO3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZ4bXNvbm9ybWFsIj48c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPkNyaXN0aWFuPC9zcGFuPjx1PjwvdT48dT48L3U-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMjcxIiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDoyMDMuNTVwdDtib3JkZXI6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Im1fODAxMTY1NzcwMTY0MTk1NjI3Nnhtc29ub3JtYWwiIGFsaWduPSJyaWdodCIgc3R5bGU9InRleHQtYWxpZ246cmlnaHQiPg0KPHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj4zPC9zcGFuPjx1PjwvdT48dT48L3U-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMTM4IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDoxMDMuOHB0O2JvcmRlcjpub25lO2JvcmRlci1ib3R0b206c29saWQgIzliYzJlNiAxLjBwdDtwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCIgYWxpZ249InJpZ2h0IiBzdHlsZT0idGV4dC1hbGlnbjpyaWdodCI-DQo8c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPjk8L3NwYW4-PHU-PC91Pjx1PjwvdT48L3A-DQo8L3RkPg0KPHRkIHdpZHRoPSI1NCIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6NDAuN3B0O2JvcmRlcjpub25lO2JvcmRlci1ib3R0b206c29saWQgIzliYzJlNiAxLjBwdDtwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCIgYWxpZ249InJpZ2h0IiBzdHlsZT0idGV4dC1hbGlnbjpyaWdodCI-DQo8c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPjEyPC9zcGFuPjx1PjwvdT48dT48L3U-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iNzYiIG5vd3JhcD0iIiB2YWxpZ249ImJvdHRvbSIgc3R5bGU9IndpZHRoOjU2LjhwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICM5YmMyZTYgMS4wcHQ7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Im1fODAxMTY1NzcwMTY0MTk1NjI3Nnhtc29ub3JtYWwiIGFsaWduPSJyaWdodCIgc3R5bGU9InRleHQtYWxpZ246cmlnaHQiPg0KPHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj40LDAwPC9zcGFuPjx1PjwvdT48dT48L3U-PC9wPg0KPC90ZD4NCjwvdHI-DQo8dHIgc3R5bGU9ImhlaWdodDoxNC41cHQiPg0KPHRkIHdpZHRoPSI0OSIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6MzcuMDVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6c29saWQgIzliYzJlNiAxLjBwdDtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7Ym9yZGVyLXJpZ2h0Om5vbmU7YmFja2dyb3VuZDojZGRlYmY3O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZ4bXNvbm9ybWFsIj48c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPkphaW1lPC9zcGFuPjx1PjwvdT48dT48L3U-PC9wPg0KPC90ZD4NCjx0ZCB3aWR0aD0iMjcxIiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDoyMDMuNTVwdDtib3JkZXI6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7YmFja2dyb3VuZDojZGRlYmY3O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZ4bXNvbm9ybWFsIiBhbGlnbj0icmlnaHQiIHN0eWxlPSJ0ZXh0LWFsaWduOnJpZ2h0Ij4NCjxzcGFuIHN0eWxlPSJjb2xvcjpibGFjayI-Mzwvc3Bhbj48dT48L3U-PHU-PC91PjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjEzOCIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6MTAzLjhwdDtib3JkZXI6bm9uZTtib3JkZXItYm90dG9tOnNvbGlkICM5YmMyZTYgMS4wcHQ7YmFja2dyb3VuZDojZGRlYmY3O3BhZGRpbmc6MGNtIDMuNXB0IDBjbSAzLjVwdDtoZWlnaHQ6MTQuNXB0Ij4NCjxwIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZ4bXNvbm9ybWFsIiBhbGlnbj0icmlnaHQiIHN0eWxlPSJ0ZXh0LWFsaWduOnJpZ2h0Ij4NCjxzcGFuIHN0eWxlPSJjb2xvcjpibGFjayI-Mzwvc3Bhbj48dT48L3U-PHU-PC91PjwvcD4NCjwvdGQ-DQo8dGQgd2lkdGg9IjU0IiBub3dyYXA9IiIgdmFsaWduPSJib3R0b20iIHN0eWxlPSJ3aWR0aDo0MC43cHQ7Ym9yZGVyOm5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjOWJjMmU2IDEuMHB0O2JhY2tncm91bmQ6I2RkZWJmNztwYWRkaW5nOjBjbSAzLjVwdCAwY20gMy41cHQ7aGVpZ2h0OjE0LjVwdCI-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCIgYWxpZ249InJpZ2h0IiBzdHlsZT0idGV4dC1hbGlnbjpyaWdodCI-DQo8c3BhbiBzdHlsZT0iY29sb3I6YmxhY2siPjY8L3NwYW4-PHU-PC91Pjx1PjwvdT48L3A-DQo8L3RkPg0KPHRkIHdpZHRoPSI3NiIgbm93cmFwPSIiIHZhbGlnbj0iYm90dG9tIiBzdHlsZT0id2lkdGg6NTYuOHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lO2JvcmRlci1ib3R0b206c29saWQgIzliYzJlNiAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgIzliYzJlNiAxLjBwdDtiYWNrZ3JvdW5kOiNkZGViZjc7cGFkZGluZzowY20gMy41cHQgMGNtIDMuNXB0O2hlaWdodDoxNC41cHQiPg0KPHAgY2xhc3M9Im1fODAxMTY1NzcwMTY0MTk1NjI3Nnhtc29ub3JtYWwiIGFsaWduPSJyaWdodCIgc3R5bGU9InRleHQtYWxpZ246cmlnaHQiPg0KPHNwYW4gc3R5bGU9ImNvbG9yOmJsYWNrIj4yLDAwPC9zcGFuPjx1PjwvdT48dT48L3U-PC9wPg0KPC90ZD4NCjwvdHI-DQo8L3Rib2R5Pg0KPC90YWJsZT4NCjxwIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZ4bXNvbm9ybWFsIj4mbmJzcDs8dT48L3U-PHU-PC91PjwvcD4NCjxwIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZ4bXNvbm9ybWFsIj5EZSB0b2RhcyBmb3JtYXMsIGNyZW8gcXVlIGxhcyBob3JhcyBlbiBjYWRhIHVuYSBkZSBsYXMgYXNpZ25hdHVyYXMgcG9yIHNlcGFyYWRvIG5vIGltcG9ydGFuIG11Y2hvOyBsbyBtw6FzIGltcG9ydGFudGUgZXMgZWwgdG90YWwgZGUgaG9yYXMgcG9ycXVlIGFzw60gbm9zIHBvZGVtb3MgY29vcmRpbmFkb3IgeSByZXBhcnRpciBlbnRyZSBsYXMgZG9zLCBxdWUgdmFuIGEgZGFyc2UNCiBsYSBtaXNtYSBzZW1hbmEgKGRlbCAyNCBhbCAyOCBkZSBzZXB0aWVtYnJlKS48dT48L3U-PHU-PC91PjwvcD4NCjxwIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZ4bXNvbm9ybWFsIj4mbmJzcDs8dT48L3U-PHU-PC91PjwvcD4NCjxwIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZ4bXNvbm9ybWFsIj5TaSBhbGd1aWVuIHRpZW5lIGFsZ3VuYSBzdWdlcmVuY2lhLCBpZGVhLCBvIHF1aWVyZSBkYXIgYWxnbyBlbiBjb25jcmV0bywgcXVlIGxvIGRpZ2EgdGFtYmnDqW4sIHF1ZSBhc8OtIHNlcsOhIG3DoXMgZsOhY2lsIGVsIHJlcGFydG8gOi0pPHU-PC91Pjx1PjwvdT48L3A-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCI-Jm5ic3A7PHU-PC91Pjx1PjwvdT48L3A-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCI-UmVjb3JkYWQgcG9uZXIgZW4gY29waWEgdGFtYmnDqW4gbGFzIGRpcmVjY2lvbmVzIOKAnHBpbG90b-KAnS4NCjx1PjwvdT48dT48L3U-PC9wPg0KPHAgY2xhc3M9Im1fODAxMTY1NzcwMTY0MTk1NjI3Nnhtc29ub3JtYWwiPiZuYnNwOzx1PjwvdT48dT48L3U-PC9wPg0KPHAgY2xhc3M9Im1fODAxMTY1NzcwMTY0MTk1NjI3Nnhtc29ub3JtYWwiPlZhbW9zIGhhYmxhbmRv4oCmPHU-PC91Pjx1PjwvdT48L3A-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCI-Jm5ic3A7PHU-PC91Pjx1PjwvdT48L3A-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCI-VW4gc2FsdWRvLCBncmFjaWFzITx1PjwvdT48dT48L3U-PC9wPg0KPHAgY2xhc3M9Im1fODAxMTY1NzcwMTY0MTk1NjI3Nnhtc29ub3JtYWwiPlZpY2VudGU8dT48L3U-PHU-PC91PjwvcD4NCjxwIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZ4bXNvbm9ybWFsIj4mbmJzcDs8dT48L3U-PHU-PC91PjwvcD4NCjxkaXY-DQo8ZGl2IHN0eWxlPSJib3JkZXI6bm9uZTtib3JkZXItdG9wOnNvbGlkICNlMWUxZTEgMS4wcHQ7cGFkZGluZzozLjBwdCAwY20gMGNtIDBjbSI-DQo8cCBjbGFzcz0ibV84MDExNjU3NzAxNjQxOTU2Mjc2eG1zb25vcm1hbCI-PGI-RGU6PC9iPiBDcmlzdGlhbiBHb256w6FsZXogR2FyY8OtYSAmbHQ7PGEgaHJlZj0ibWFpbHRvOmdvbnphbGV6Z2FyY2lhY3Jpc3RpYW5AaG90bWFpbC5jb20iIHRhcmdldD0iX2JsYW5rIj5nb256YWxlemdhcmNpYWNyaXN0aWFuQGhvdG1haWwuY29tPC9hPiZndDsNCjxiPkVuIG5vbWJyZSBkZSA8L2I-Q3Jpc3RpYW4gR29uesOhbGV6IEdhcmPDrWE8YnI-DQo8Yj5FbnZpYWRvIGVsOjwvYj4gbWFydGVzLCA0IGRlIHNlcHRpZW1icmUgZGUgMjAxOCAxODo0Nzxicj4NCjxiPlBhcmE6PC9iPiBWSUNFTlRFIEdBUkNJQSBESUFaICZsdDs8YSBocmVmPSJtYWlsdG86Z2FyY2lhdmljZW50ZUB1bmlvdmkuZXMiIHRhcmdldD0iX2JsYW5rIj5nYXJjaWF2aWNlbnRlQHVuaW92aS5lczwvYT4mZ3Q7OyBFRFdBUkQgUk9MQU5ETyBOVcORRVogVkFMREVaICZsdDs8YSBocmVmPSJtYWlsdG86bnVuZXplZHdhcmRAdW5pb3ZpLmVzIiB0YXJnZXQ9Il9ibGFuayI-bnVuZXplZHdhcmRAdW5pb3ZpLmVzPC9hPiZndDs7DQo8YSBocmVmPSJtYWlsdG86cGlsb3RvLmRjbUBnbWFpbC5jb20iIHRhcmdldD0iX2JsYW5rIj5waWxvdG8uZGNtQGdtYWlsLmNvbTwvYT47IDxhIGhyZWY9Im1haWx0bzpwaWxvdG8ubXN3YWRtQGdtYWlsLmNvbSIgdGFyZ2V0PSJfYmxhbmsiPg0KcGlsb3RvLm1zd2FkbUBnbWFpbC5jb208L2E-PGJyPg0KPGI-QXN1bnRvOjwvYj4gRGlzdHJpYnVjacOzbiBkZSBob3Jhczx1PjwvdT48dT48L3U-PC9wPg0KPC9kaXY-DQo8L2Rpdj4NCjxwIGNsYXNzPSJtXzgwMTE2NTc3MDE2NDE5NTYyNzZ4bXNvbm9ybWFsIj4mbmJzcDs8dT48L3U-PHU-PC91PjwvcD4NCjxkaXYgaWQ9Im1fODAxMTY1NzcwMTY0MTk1NjI3NnhfbV8tNTY1ODAyODk2NjkxMzU1MTUyOWRpdnRhZ2RlZmF1bHR3cmFwcGVyIj4NCjxkaXYgaWQ9Im1fODAxMTY1NzcwMTY0MTk1NjI3NnhfbV8tNTY1ODAyODk2NjkxMzU1MTUyOWRpdnRhZ2RlZmF1bHR3cmFwcGVyIj4NCjxwPjxzcGFuIHN0eWxlPSJmb250LXNpemU6MTIuMHB0O2NvbG9yOmJsYWNrIj5CdWVuYXM6PC9zcGFuPjx1PjwvdT48dT48L3U-PC9wPg0KPHA-PHNwYW4gc3R5bGU9ImZvbnQtc2l6ZToxMi4wcHQ7Y29sb3I6YmxhY2siPiZuYnNwOzwvc3Bhbj48dT48L3U-PHU-PC91PjwvcD4NCjxwPjxzcGFuIHN0eWxlPSJmb250LXNpemU6MTIuMHB0O2NvbG9yOmJsYWNrIj5jb24gZWwgY29taWVuem8gZGUgY3Vyc28geSB0cmF0YW5kbyBkZSBvcmdhbml6YXJtZSwgbWUgZ3VzdGFyw61hIHNhYmVyIGN1YWwgdmEgYSBzZXIgbGEgZGlzdHJpYnVjacOzbiBkZSBob3JhcyBkZSBhbWJhcyBhc2lnbmF0dXJhcyBwYXJhIGFzw60gcG9kZXIgcGxhbmVhciBlbCBjYWxlbmRhcmlvIGFjYWTDqW1pY28geSBwcmVwYXJhciBsYXMgYXNpZ25hdHVyYXMgY29tbyB0b2NhLjwvc3Bhbj48dT48L3U-PHU-PC91PjwvcD4NCjxwPjxzcGFuIHN0eWxlPSJmb250LXNpemU6MTIuMHB0O2NvbG9yOmJsYWNrIj4mbmJzcDs8L3NwYW4-PHU-PC91Pjx1PjwvdT48L3A-DQo8cD48c3BhbiBzdHlsZT0iZm9udC1zaXplOjEyLjBwdDtjb2xvcjpibGFjayI-U2FsdWRvcyw8YnI-DQpDcmlzdGlhbjwvc3Bhbj48dT48L3U-PHU-PC91PjwvcD4NCjwvZGl2Pg0KPC9kaXY-DQo8L2Rpdj4NCjwvZGl2Pg0KPC9ibG9ja3F1b3RlPg0KPC9kaXY-DQo8L2Rpdj4NCjwvZGl2Pg0KPC9kaXY-DQo8L2Jsb2NrcXVvdGU-DQo8L2Rpdj4NCjwvZGl2Pg0KPC9ibG9ja3F1b3RlPg0KPC9kaXY-DQo8L2JvZHk-DQo8L2h0bWw-DQo=",
#                     "size": 34733
#                 },
#                 "filename": "",
#                 "headers": [
#                     {
#                         "name": "Content-Type",
#                         "value": "text/html; charset=\"utf-8\""
#                     },
#                     {
#                         "name": "Content-Transfer-Encoding",
#                         "value": "base64"
#                     }
#                 ],
#                 "mimeType": "text/html",
#                 "partId": "1"
#             }
#         ]
#     },
#     "sizeEstimate": 65368,
#     "snippet": "Hola a todos, Yo estoy de vacaciones esta semana y no ando por Asturias, la semana que viene ya empiezo a trabajar otra vez y no puedo ir a la reuni\u00f3n esa que comentabais si finalmente se organiza. En",
#     "threadId": "165a4311d9e71094"
# }
