/* jshint node: true, devel: true */
'use strict';

const
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),
  request = require('request'),
  Uber = require('node-uber'); // Capitalized i'm srry fam pls don't hate me for this

var uber = new Uber({
    client_id: (process.env.UBER_ID) ?
      process.env.UBER_ID :
      config.get('uberId'),

    client_secret: (process.env.UBER_SECRET) ?
      process.env.UBER_SECRET :
      config.get('uberSecret'),

    server_token: (process.env.UBER_TOKEN) ?
      process.env.UBER_TOKEN :
      config.get('uberToken'),

    redirect_uri: 'https://9dcbd48d.ngrok.io/api/callback',

    name: (process.env.UBER_BOT_NAME) ?
      process.env.UBER_BOT_NAME :
      config.get('uberBotName'),

    language: 'en_US' // optional, defaults to en_US
});

var app = express();
app.set('port', process.env.PORT || 5000);
// app.set('view engine', 'ejs');
app.use(bodyParser.json());
// app.use(express.static('public'));

/*
 * Be sure to setup your config values before running this code. You can
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ?
    process.env.MESSENGER_APP_SECRET :
    config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
    process.env.MESSENGER_VALIDATION_TOKEN :
    config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
    process.env.MESSENGER_PAGE_ACCESS_TOKEN :
    config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and
// assets located at this address.
// const SERVER_URL = (process.env.MESSENGER_SERVER_URL);
const SERVER_URL = (process.env.MESSENGER_SERVER_URL) ?
    process.env.MESSENGER_SERVER_URL :
    config.get('serverURL');


if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
} else {
    console.log("- VALUES VALIDATED");
}

app.get('/webhook', function(req, res) {
    console.log(res);
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);
  }
});

app.post('/webhook', function (req, res) {
  var data = req.body;

  console.log('');
  console.log('Message received -----------------------------------------------------------------------------');
  console.log('');

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

  // Authorization Code should be generated per user by the developer. This will
  // be passed to the Account Linking callback.
  var authCode = "1234567890";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

 // Uber API
 app.get('/api/login', function(request, response) {
     console.log("Veryfying ya user m8");
     var url = uber.getAuthorizeUrl(['places']);
     console.log(url)
     response.redirect(url);
 });

 app.get('/api/callback', function(request, response) {
     uber.authorization({
         authorization_code: request.query.code
     }, function(err, access_token, refresh_token) {
         if (err) {
             console.error(err);
         } else {
             console.log(access_token);
             console.log(refresh_token);

             // store the user id and associated access token
             // redirect the user back to your actual app
             // TODO
             console.log("Authentication successful --------------------------------->");
             response.redirect(' https://www.messenger.com/closeWindow/?image_url=IMAGE_URL&display_text=DISPLAY_TEXT');

         }
     });
 });

 // Uber API END

function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger'
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam,
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}

function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:",
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s",
      messageId, appId, metadata);
    return;
  } else if (quickReply) {

    var quickReplyPayload = quickReply.payload;
    console.log("Quick reply for message %s with payload %s", messageId, quickReplyPayload);

    // Location variables
    var curLong, curLat;
    var destLong, destLat;

    if (quickReply.type == 'location') {
        // Set Current Location for user
        curLong = quickReply.payload.coordinates.long;
        curLat = quickReply.payload.coordinates.lat;

        // TODO: Request User Destination Location
        // sendTextMessage(senderID, "Sweet! Please send me your destination location now. Just hit that button below. Come on now, do it!");
        // requestDestinationLocation(senderID);

        // Temporary Segue to ride type
        // sendTextMessage(senderID, "What type of transportation would you like?");
        sendUberOptions(senderID);
    } else {
        if (messageText == 'Uber') {
            setupUber(senderID);
        } else {
            sendTextMessage(senderID, "Quick reply tapped");
        }
    }

    return;
  }

  if (messageText) {

    // If we receive a text message, check to see if it matches any special
    // keywords and send back the corresponding example. Otherwise, just echo
    // the text we received.
    switch (messageText) {
      case 'image':
        sendImageMessage(senderID);
        break;

      case 'gif':
        sendGifMessage(senderID);
        break;

      case 'audio':
        sendAudioMessage(senderID);
        break;

      case 'video':
        sendVideoMessage(senderID);
        break;

      case 'file':
        sendFileMessage(senderID);
        break;

      case 'button':
        sendButtonMessage(senderID);
        break;

      case 'generic':
        sendGenericMessage(senderID);
        break;

      case 'receipt':
        sendReceiptMessage(senderID);
        break;

      case 'quick reply':
        sendQuickReply(senderID);
        break;

      case 'read receipt':
        sendReadReceipt(senderID);
        break;

      case 'typing on':
        sendTypingOn(senderID);
        break;

      case 'typing off':
        sendTypingOff(senderID);
        break;

      case 'account linking':
        sendAccountLinking(senderID);
        break;

    case 'uber':
        requestCurrentLocation(senderID);
        break;

      default:
        sendTextMessage(senderID, messageText);
    }
  } else if (messageAttachments) {
    sendTextMessage(senderID, "Message with attachment received");
  }
}

function requestCurrentLocation(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message:{
            text: "Please share your location:",
            quick_replies: [
                {
                    content_type: "location",
                }
            ]
        }
    };

    callSendAPI(messageData);
}

function sendUberOptions(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: "Please select your ride:",
            quick_replies: [
                {
                    content_type: "location",
                }
            ]
        }
    };

    callSendAPI(messageData);
}

function sendGetStartedMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: "Welcome to UberLyft! Lets get you setup so that you can seamlessly call an Uber or a Lyft later!"
        }
    };

    callSendAPI(messageData);
}

function setupUber(recipientId, callback) {
    var messageData = {
      recipient: {
        id: recipientId
      },
      message: {
        attachment: {
          type: "template",
          payload: {
            template_type: "button",
            text: "Let's verify your Uber account.",
            buttons:[{
              type: "web_url",
              url: "https://9dcbd48d.ngrok.io/api/login",
              title: "Verify Uber Account"
            }]
          }
        }
      }
    };

    callSendAPI(messageData, callback);
}

function setupLyft(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: "Now lets verify your Lyft account.",
            quick_replies: [
                {
                    "content_type": "text",
                    "title": "Lyft",
                    "payload":"VERIFY_LYFT_BUTTON"
                }
            ]
        }
    };

    callSendAPI(messageData);
}

function defaultCallback() {
  console.log("Default Callback ran------------------------------------------------------");
}

function receivedPostback(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfPostback = event.timestamp;

    // The 'payload' param is a developer-defined field which is set in a postback
    // button for Structured Messages.
    var payload = event.postback.payload;

    console.log("Received postback for user %d and page %d with payload '%s' " + "at %d", senderID, recipientID, payload, timeOfPostback);

    // When a postback is called, we'll send a message back to the sender to
    // let them know it was successful
    if (payload == "GET_STARTED_BUTTON") {
        // sendGetStartedMessage(senderID);
        console.log("GET STARTED INITIATED, SETTING UP UBER AUTH---------------------------------------------------------------------");
        // STEP 1
        setupUber(senderID, requestCurrentLocation);
    } else if (payload == "VERIFY_LYFT_BUTTON") {
        // Verify Lyft account and let user know it's done
        // Then move on to next part of user story
    } else {
        sendTextMessage(senderID, "Postback called");
    }
}

//
// REDUNDANT CODE BELOW
//
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s",
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}

function callSendAPI(messageData, callback) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s",
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s",
        recipientId);

      }
    } else {
      console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
    }
  });
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;
