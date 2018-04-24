'use strict';
var url = require('url');
var http = require('http');
var fs = require('fs');
var formidable = require("formidable");
var util = require('util');
var moment = require('moment');
var secureRandom = require('secure-random');
var jsonfile = require('jsonfile');
var cmd=require('node-cmd');

var crypto = require('crypto');
const commandLineArgs = require('command-line-args');

const optionDefinitions = [
    // option 'blockchain' set only when fabric blockchain network is contructed in docker
    { name: 'blockchain', alias: 'b', type: Boolean, defaultOption: false},
    { name: 'test', alias: 't', type: String }
]

const cmd_options = commandLineArgs(optionDefinitions);


var bodyParser = require('body-parser');
const winston = require('winston');
const tsFormat = () => (moment().format("YYYY-MM-DD HH:mm:ss"));
const logger = new (winston.Logger)({
  transports: [
    // colorize the output to the console
    new (winston.transports.Console)({
        timestamp: tsFormat,
        colorize: true 
    })
  ]
});

logger.level = 'debug';

// var lottery_channel = require("basic_fabric_loc/app/create-channel.js");
// var join_channel = require("basic_fabric_loc/app/join-channel.js");
// var install_chaincode = require("basic_fabric_loc/app/install-chaincode.js");

/* var instantiate_chaincode = require("basic_fabric_loc/app/instantiate-chaincode.js"); */
// var invoke_chaincode = require("basic_fabric_loc/app/invoke-transaction.js");
// var query_chaincode = require("basic_fabric_loc/app/query.js");  

var express = require("express");
var app = express();
var LotteryChainInterface = {};

var LotteryCAInterface = {};

var basic_fabric_loc="./fabric-internals";

var getScript = require("./default-script.js");
// console.log(getScript.script);
var appPort = 1185;

function start_server(app, port) {
    app.listen(port, function() {
        logger.info('Server is now listening on '+port);
    });
}

// Cross domain issue fixed. Referenced following link.
// http://stackoverflow.com/questions/28515351/xmlhttprequest-cannot-load-http-localhost3000-get
var allowCrossDomain = function(req, res, next) {
        // Website you wish to allow to connect
    res.setHeader('Access-Control-Allow-Origin', '*');

    // Request methods you wish to allow
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');

    // Request headers you wish to allow
    res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type');

    // Set to true if you need the website to include cookies in the requests sent
    // to the API (e.g. in case you use sessions)
    res.setHeader('Access-Control-Allow-Credentials', true);
   next();
}

app.use(allowCrossDomain);
app.use(bodyParser.urlencoded());

// Allow client to use /lib
app.use("/lib", express.static(__dirname + "/lib"));
app.use("/style", express.static(__dirname + "/style"));

app.get('/', function(req, res){
    response_client_html(res, "index.html");
});

app.get('/all', function(req, res) {
    displayForm(res);
});

app.get('/index.html', function(req, res) {
    response_client_html(res, "index.html");
});

app.get('/subscribe.html', function(req, res) {
    response_client_html(res, "subscribe.html");
});

app.get('/open-lottery.html', function(req, res) {
    response_client_html(res, "open-lottery.html");
});

app.post('/subscribe', function(req, res) {
    logger.info("/subscribe")
    var args = [];
    var function_name = req.body.function_name;
    var mhash = req.body.mhash;
    var memberName = req.body.memberName;
    var currtimestamp = req.body.currtimestamp;
    console.log(function_name, mhash, memberName, currtimestamp);
    args[0] = function_name;
    args[1] = mhash;
    args[2] = memberName;
    args[3] = currtimestamp;

    var adminReq = {
        enrollmentID: 'admin',
        enrollmentSecret: 'adminpw'
    }
    var NewIdentity = {
        CAHostAddress: "http://localhost:7054",
        enrollmentID: memberName,
        enrollmentSecret: "",
        role: "user",
        affiliation: "org1.department1",
        MaxEnrollments: "-1",
    }; 
    var hashedPubkey;
    res.write("hello");
    LotteryCAInterface.register(adminReq, NewIdentity, res)
    .then(function (pubKey) {
        // console.log("this is pubkey " + pubKey.pubKeyHex + "outside of register func");
        console.log("this is pubkey " + pubKey._key.pubKeyHex + "outside of register func");
        var userPubKey = pubKey._key.pubKeyHex;
        hashedPubkey = crypto.createHash('sha256').update(userPubKey).digest('base64');
        console.log('Hased Public key: ' , hashedPubkey);
        args[2] = hashedPubkey;

        return LotteryChainInterface.invoke_chaincode(args);
    }).then(function() {
        res.write(hashedPubkey);
        res.end();
    });
});


app.post('/register-lottery', function(req, res) {
    processAllFieldsOfTheForm(req, res);
});

// check the result( = check the winner(s))
app.post('/check', function(req, res) {
    logger.info("/check")
    var args = [];
    /* args[0] = req.body.function_name; */
    args[0] = "check";
    args[1] = req.body.mhash;
    args[2] = "random!";

    logger.info("args[0]: " + args[0]);
    logger.info("args[1]: " + args[1]);
    logger.info("args[2]: " + args[2]);

    LotteryChainInterface.invoke_chaincode(args)
    .then(function(responsePayloads) {
        // var responseStr = responsePayloads.toString('utf-8');
        logger.info("After response Check the results: " + responsePayloads);
        res.writeHead(200, {
            // 'Content-Type': 'application/json',
            'Content-Type': 'text/plain',
        });
        /* res.write(JSON.stringify(responsePayloads)); */
        res.write(responsePayloads);
        res.end();
    });
});

app.post('/verify', function(req, res) {
    logger.info("/verify requested");
    var args = [];
    args[0] = "verify";
    args[1] = req.body.mhash;
    LotteryChainInterface.invoke_chaincode(args)
    .then(function(responsePayloads) {
        // var responseStr = responsePayloads.toString('utf-8');
        logger.info("After response Check the results: " + responsePayloads);
        res.writeHead(200, {
            // 'Content-Type': 'application/json',
            'Content-Type': 'text/plain',
        });
        /* res.write(JSON.stringify(responsePayloads)); */
        res.write(responsePayloads);
        res.end();
    });
});

app.post('/cc-query-all-events', function(req, res) {
    logger.info("/cc-query-all-events requested")
    
    // 여기에 체인코드 query_all_lottery_event_hash()
    var args = [];
    args[0] = "query_all_lottery_event_hash";

    var query_res = LotteryChainInterface.query_chaincode(args);

    query_res.then(function (responsePayloads) {
        logger.info("responsePayloads type: " + typeof responsePayloads);
        logger.info("responsePayloads length: " + responsePayloads.length);
        // logger.info("responsePayloads " + util.inspect({responsePayloads}));
        // logger.info("object[0]'s key' " + Object.keys(responsePayloads[0]));
        logger.info("object[0] " + responsePayloads[0]);
        var responseStr = responsePayloads.toString('utf-8');
        logger.info("responseStr: " + responseStr);

        // console.log("utf8:" + responsePayloads[0].toString('hex'));

        /* for (var i = 0, l = responsePayloads[0].length; i < l; i++) {
            var v = responsePayloads[0][i];
            console.log(v[i]);
        } */
        // console.log("object[1] " + responsePayloads[1]);
        res.writeHead(200, {
            // 'Content-Type': 'application/json',
            'Content-Type': 'text/plain',
        });
        // res.write(JSON.stringify(responsePayloads));
        res.write(responsePayloads.toString('utf-8'));
        res.end();

    }); 
});

function response_client_html(res, filename) {
    fs.readFile(filename, function (err, data) {
        res.writeHead(200, {
            'Content-Type': 'text/html',
        });
        res.write(data);
        res.end();
    });
    logger.info(filename + " requested");
}

// client enrollment request
app.post('/enrollment', function(req, res) {
    logger.info("/enrollment Requested");
    var CAHostAddress, EnrollmentID, EnrollmentSecret;
    // console.log(util.inspect({req}));
    var p = new Promise(function(resolve, reject) {
        CAHostAddress = req.body.CAHostAddress;
        EnrollmentID = req.body.EnrollmentID;
        EnrollmentSecret = req.body.EnrollmentSecret;
        var user_req = {
            CAHostAddress: CAHostAddress,
            enrollmentID: EnrollmentID,
            enrollmentSecret: EnrollmentSecret
        }
        res.writeHead(200, {
            'content-type' : 'text/plain'
        }); 
        LotteryCAInterface.enroll(user_req, res);
    }).then(function() {
        res.write("Successfully enrolled with " + EnrollmentID + " to " + CAHostAddress);
        res.end(); 
    });
});

app.post('/register-identity', function(req, res) {
    logger.info("/register-identity Requested");
    var CAHostAddress, EnrollmentID, EnrollmentSecret, MspId;
    var Affiliation, Role, MaxEnrollments;
    var hf_Registrar_Roles, hf_Registrar_DelegateRoles, hf_Revoker;
    // console.log(util.inspect({req}));
    // Init
    CAHostAddress = req.body.CAHostAddress;
    EnrollmentID = req.body.EnrollmentID;
    EnrollmentSecret = req.body.EnrollmentSecret;
    MspId = req.body.MspId;
    Affiliation = req.body.Affiliation;
    Role = req.body.Role;
    MaxEnrollments = req.body.MaxEnrollments;
    hf_Registrar_Roles = req.body.hf_Registrar_Roles;
    hf_Registrar_DelegateRoles = req.body.hf_Registrar_DelegateRoles;
    hf_Revoker = req.body.hf_Revoker;
    res.writeHead(200, {
        'content-type' : 'text/plain'
    }); 
    var p = new Promise(function(resolve, reject) {
        var adminReq = {
            enrollmentID: 'admin',
            enrollmentSecret: 'adminpw'
        }
        var NewIdentity = {
            CAHostAddress: CAHostAddress,
            enrollmentID: EnrollmentID,
            enrollmentSecret: EnrollmentSecret,
            role: Role,
            affiliation: Affiliation,
            MaxEnrollments: MaxEnrollments,
            attrs: [
                    {
                        name : "hf.Registrar.Roles",
                        value : req.body.hf_Registrar_Roles
                    },
                    {
                        name : "hf.Registrar.DelegateRoles",
                        value : req.body.hf_Registrar_DelegateRoles
                    },
                    {
                        name : "hf.Revoker",
                        value: req.body.hf_Revoker
                    }
            ],
        }; 
        console.log(util.inspect({NewIdentity}));
        // At now, only admin user can register new identity
        return LotteryCAInterface.register(adminReq, NewIdentity, res);
    }).then((result) => {
        logger.info("result: " + result);
        res.writeHead(200, {
            'content-type' : 'text/plain'
        }); 
        res.write("Successfully enrolled with " + EnrollmentID + " to " + CAHostAddress);
        res.end(); 
    }, (err) => {
        logger.debug("enrollment error1");
    }).catch((err) => {
        logger.debug("enrollment error2");
    });
    p.then(() => {
    
    })

});

app.post('/start-blockchain', function(req, res) {
    logger.info("/start-blockchain Requested");
    var p = new Promise(function(resolve, reject) {
        cmd.get(
            'pwd',
            function(err, data, stderr) {
                console.log("Starting network...");
                cmd.get(
                    'make setup -C ' + data.replace(/[^\x20-\x7E]/gmi, ""),
                    function(err, _data, stderr) {
                        console.log(_data);
                        promise_response("Started Hyperledger/Fabric Blockchain Network", res);
                    }
                ); 
            }
        );
        resolve("Success!");
    }).then(function () {

    });
    // p.then(promise_response("Started Hyperledger/Fabric Blockchain Network", res));
});

function promise_response(log, res) {
    res.writeHead(200, {
        'content-type' : 'text/plain'
    });

    res.write(log);
    res.end();
}

app.post('/terminate-blockchain', function(req, res) {
    logger.info("/terminate-blockchain Requested");
    var p = new Promise(function(resolve, reject) {
        cmd.get(
            'pwd',
            function(err, data, stderr) {
                console.log("Terminating network...");
                cmd.get(
                    'make term -C ' + data.replace(/[^\x20-\x7E]/gmi, ""),
                    function(err, _data, stderr) {
                        console.log(_data);
                        promise_response("Terminated Hyperledger/Fabric Blockchain Network", res);
                    }
                ); 
            }
        );
        resolve("Success!");
    }).then(function () {

    });
});



app.post('/create-channel', function(req, res) {
    logger.info("/created-channel Requested");
    var create_response;
    var p = new Promise(function(resolve, reject) {
        create_response = LotteryChainInterface.create_channel();
        if (true) {
            // resolve function should be invoked to proceed next pending function.
            resolve("Success!");
        }  else {
            reject("Fails");
        }
    });
    p.then(function () {
        res.writeHead(200, {
            'content-type' : 'text/plain'
        });

        res.write("Channel created successfully: " +  create_response);
        res.end();
    });

});

app.post('/join-channel', function(req, res) {
    logger.info("/join-channel Requested");
    var join_response;
    var p = new Promise(function(resolve, reject) {
        join_response = LotteryChainInterface.join_channel();
        if (true) {
            // resolve function should be invoked to proceed next pending function.
            resolve("Success!");
        }  else {
            reject("Fails");
        }
    });
    
    p.then(function() {
        res.writeHead(200, {
            'content-type' : 'text/plain'
        });
        res.write("Peer joined with channel: " + join_response);
        res.end();
    });
 
});

app.post('/install-chaincode', function(req, res) {
    logger.info("/install-chaincode Requested");
    var p = new Promise(function(resolve, reject) {
    LotteryChainInterface.install_chaincode();
        if (true) {
            resolve("Success!");
        }  else {
            reject("Fails");
        }
    });
    p.then(function() {
        res.writeHead(200, {
            'content-type' : 'text/plain'
        });
        res.write("Installed chaincode successfully");
        res.end();
    });
});

app.post('/instantiate-chaincode', function(req, res) {
    logger.info("/instantiate_chaincode Requested");
    /* var p = new Promise(function(resolve, reject) {
        if (true) {
            resolve("Success!");
        }  else {
            reject("Fails");
        }
    }); */
    LotteryChainInterface.instantiate_chaincode()
    .then(function() {
        res.writeHead(200, {
            'content-type' : 'text/plain'
        });
        res.write("Chaincode Initialized successfully");
        res.end();
    });
    /* p.then(LotteryChainInterface.instantiate_chaincode())
    .then(function() {
        res.writeHead(200, {
            'content-type' : 'text/plain'
        });
        res.write("Chaincode Initialized successfully");
        res.end();
    }); */
});

app.post('/invoke-chaincode', function(req, res) {
    logger.info("/invoke-chaincode Requested");

    /* var p = new Promise(function(resolve, reject) {
        if (true) {
            resolve("Success!");
        }  else {
            reject("Fails");
        }
    }); */
    LotteryChainInterface.invoke_chaincode()
    .then(function() {
        res.writeHead(200, {
            'content-type' : 'text/plain'
        });
        res.write("Invoke Result: ");
        res.end();
    })
    /* p.then(LotteryChainInterface.invoke_chaincode())
    .then(function() {
        res.writeHead(200, {
            'content-type' : 'text/plain'
        });
        res.write("Invoke Result: ");
        res.end();
    }); */
});

app.post('/query-chaincode', function(req, res) {
    logger.info("/query-chaincode Requested");

    var query_res = LotteryChainInterface.query_chaincode();
    logger.info("response_payloads type: " + typeof response_payloads);

    query_res.then(function (value){
        logger.info("response_payloads type: " + value);

        res.writeHead(200, {
            'content-type' : 'text/plain'
        });
        res.write("" + value);
        res.end();
    });

});

app.post('/register-user', function(req, res) {
    logger.info("/register-user Requested");

    res.writeHead(200, {
        'content-type' : 'text/plain'
    });
    res.write("hi");
    res.end();
    
});

var func_numargs_map = new Object();
// including function name itself
func_numargs_map["create_lottery_event"] = 7;
func_numargs_map["query_lottery_event"] = 2;
func_numargs_map["create_target_block"] = 2;
func_numargs_map["query_target_block"] = 2;
func_numargs_map["determine_winner"] = 2;
func_numargs_map["query_winner"] = 2;
func_numargs_map["query_all_lottery"] = 2;

var FunctionType = new Object();
FunctionType["create_lottery_event"] = "invoke";
FunctionType["query_lottery_event"] = "query";
FunctionType["create_target_block"] = "invoke";
FunctionType["query_target_block"] = "query";
FunctionType["determine_winner"] = "invoke";
FunctionType["query_winner"] = "query";
FunctionType["query_all_lottery"] = "query";
const MAX_CC_ARGS = 7;

// References https://nehakadam.github.io/DateTimePicker/
function datetimeToTimestamp(datetime) {
    var timestamp;
    var tmpdt = new Date(datetime);
    timestamp = tmpdt.getTime();
    return timestamp / 1000;
}

app.post('/admin-register', function(req, res) {
    logger.info("/admin-register Requested");
})

app.post('/cc-interface', function(req, res) {
    logger.info("/cc-interface Requested");
    var invoke_info = process_invoke_args(req);
    var f_type = invoke_info.f_type;
    var args = invoke_info.args;
    console.log(f_type); console.log(args);

    // Invoke Chain Code 
    cc_interface_branch(f_type, args, res);

    // Write to 
    write_lottery_to_jsonfile(args);
});

function process_invoke_args(req) {
    var obj = req.body;
    // console.log(req.body);
    var function_name = obj.arg0;
    var args = [];
    var numargs = func_numargs_map[function_name];
    var f_type = FunctionType[function_name];
    var invoke_info = {};

    args[0] = obj.arg0;
    args[1] = obj.arg1;
    args[2] = obj.arg2;
    args[3] = obj.arg3;
    args[4] = obj.arg4;
    args[5] = obj.arg5;
    args[6] = obj.arg6;

    for (var i = 0; i < MAX_CC_ARGS - numargs; ++i) {
        args.pop();
    }

    /* console.log(function_name);
    console.log(args);  */
    invoke_info = {
        "args" : args,
        "f_type" : f_type,
    };
    return invoke_info;
}

function cc_interface_branch(f_type, args, res) {
    if (f_type == "invoke") {
        cc_interface_invoke(args, res);
    } else if (f_type == "query") {
        cc_interface_query(args, res);
    }

}

function cc_interface_invoke(args, res) {
    LotteryChainInterface.invoke_chaincode(args)
        .then(function() {
            res.writeHead(200, {
                'content-type' : 'text/plain'
            });
            res.write("Invoke Successfully");
            res.end();
        });
}

function cc_interface_query(args, res) {
    var query_res = LotteryChainInterface.query_chaincode(args);
    // console.log("response_payloads type: " + typeof response_payloads);

    query_res.then(function (value){
        console.log("response_payloads " + value);

        res.writeHead(200, {
            'content-type' : 'text/plain'
        });
        res.write("" + value);
        res.end();
    });

}
function displayForm(res) {
    fs.readFile('form.html', function (err, data) {
        res.writeHead(200, {
            'Content-Type': 'text/html',
                'Content-Length': data.length
        });
        res.write(data);
        res.end();
    });
}

// cryptographic random generator
// https://www.npmjs.com/package/secure-random
function get_cryptosecure_num() {

    var randomarray = secureRandom.randomUint8Array(10)
    console.log("Your lucky numbers:");
    var str = "";
    for (var i = 0; i < randomarray.length; i++) {
        console.log(randomarray[i]);
        str += randomarray[i].toString(16);
    }
    console.log(str);
    return str;
}

// get_cryptosecure_num();
function processAllFieldsOfTheForm(req, res) {
    var eventName;
    var datetime; // due date
    var issuedate;
    var announcementdate;
    var futureblock;
    var numOfMembers;
    var numOfWinners;
    var memberList; 
    var randomKey;
    var ManifestHash;
    var args = [];

    var form = new formidable.IncomingForm();
    form.parse(req, function (err, fields, files) {

        ManifestHash = fields.ManifestHash;
        eventName = fields.EventName;
        datetime = fields.DateTime;
        issuedate = fields.IssueDate;
        announcementdate = fields.AnnouncementDate;
        futureblock = fields.fblock;
        numOfMembers = fields.numOfMembers;
        numOfWinners = fields.numOfWinners;
        randomKey = fields.RandomKey;
        memberList = fields.MemberList;

        console.log(eventName);
        console.log(datetime, datetimeToTimestamp(datetime), typeof datetimeToTimestamp(datetime));
        console.log(issuedate, datetimeToTimestamp(issuedate),typeof datetimeToTimestamp(datetime));
        console.log(announcementdate, datetimeToTimestamp(announcementdate),typeof datetimeToTimestamp(datetime));
        console.log(futureblock);
        console.log(numOfMembers);
        console.log(numOfWinners);
        console.log(randomKey);
        console.log(memberList);
        console.log(ManifestHash);

        // format argument array to be input for chaincode
        args[0] = "create_lottery_event_hash"; // function name of chaincode
        args[1] = ManifestHash;
        args[2] = eventName;
        args[3] = datetimeToTimestamp(issuedate).toString();
        args[4] = datetimeToTimestamp(datetime).toString();
        args[5] = datetimeToTimestamp(announcementdate).toString();
        args[6] = futureblock;
        args[7] = numOfMembers;
        args[8] = numOfWinners;
        args[9] = randomKey;
        // args[9] = memberList;
        args[10] = getScript.script;

        var obj = {
            "ManifestHash" : ManifestHash,
            "EventName" : eventName,
            "IssueDate" : issuedate,
            "DueDateTime" : datetime,
            "AnnouncementDate" : announcementdate,
            "FutureTargetBlock": futureblock,
            "numOfMembers": numOfMembers,
            "numOfWinners": numOfWinners,
            "RandomKey": randomKey,
            // "MemberList": memberList,
            "script": getScript.script,
        }

        console.log(obj);
        var fname = "inputmanifests/" + "lottery-" + ManifestHash + ".json";

        jsonfile.writeFileSync(fname, obj, {spaces:2}, function(err) {
            console.log(err);
        });

        var text = "Manifest " + ManifestHash
        + "<br>\{ <br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\"EventName\":&nbsp;" + eventName
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"Status\":&nbsp;" + "1"
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"IssueDate\":&nbsp;" + issuedate
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"DueDate\":&nbsp;" + datetime
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"AnnouncementDate\":&nbsp;" + announcementdate
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"FutureBlock\":&nbsp;" + futureblock
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"numOfMembers\":&nbsp;" + numOfMembers
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"numOfWinners\":&nbsp;"+  numOfWinners
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"randomKey\":&nbsp;" + randomKey
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"MemberList\":&nbsp;" + memberList
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"WinnerList\":&nbsp;" + "UNDEFINED"
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"script\": " + getScript.script
        + "<br>"
        + "\}"

        var downtexts = [
            '<a href="/inputmanifests/lottery-"'
        ];
        res.writeHead(200, {
            'content-type' : 'text/html'
        });
        res.write('<b>Event is being processed in blokchain network. Wait a few seconds</b><br><br>');

        setTimeout(function() {
            LotteryChainInterface.invoke_chaincode(args).then(function() {
                res.write(
                    '<a href="/open-lottery.html"' + '>prev</a><br>'
                    + '<b>Lottery Manifest<br>Congratuation! You just registered lottery event successfully. Lottery event is stored in blockchain network built upon hyperledger/fabric.</b>'
                    + "<b>You can download manifest file and use it later to check result</b><br>"
                    + "<b>This manifest file is temporary. It will be change over time whenever new members joined</b><br>"
                    + '<a download href="/inputmanifests/lottery-' + ManifestHash + '.json"'  + '>download manifest</a>'
                    + '<br><br>'
                    + text
                    + "<br>"
                    + "<br>"
                );
                    
            })
        }, 500);
            
    });

    /* res.end(util.inspect({
            fields: fields,
            files: files
        })); */
}

start_server(app, appPort);
// setTimeout(e2e_test, 500);

if (cmd_options.blockchain) {
    // well working function
    console.log("e2e_test start");
    setTimeout(e2e_test, 2000);
} else {

} 


