<?php
require('db.php');
// Update with JSON

$db = new MyDB();
if(!$db){
    error_log($db->lastErrorMsg());
}

$json = json_decode(file_get_contents('php://input'), true);
if ($json) {
    $GLOBALS['json'] = $json;
    $_POST = array_merge($_POST, $json);
}


if (!isset($_POST['origin'])) {
    $_POST['origin'] = '*';
}

function reply($answer, $code = 200) {
    header('Access-Control-Allow-Origin: '.$_POST['origin']);
    header('Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With');
    http_response_code($code);
    $reply = array('status' => $code, 'origin' => $_POST['origin']);
    echo(json_encode(array_merge($reply, $answer)));
}

if ($json) { //Handling the issue of double requests/responses.
    if (isset($_POST['token']) && $db->validateToken($_POST['token'])) {
        $user = $db->getToken($_POST['token'])['user'];
        switch ($_GET['function']) {
            case 'nick':
                if ($_POST['nick']) {
                    $nick = $_POST['nick'];
                    $message = array('success' => $db->setNick($user, $nick));
                    $message['nick'] = $db->getNick($user);
                    reply($message);
                } else {
                    $message = array('nick' => $db->getNick($user));
                    reply($message);
                }
                break;
                
            case 'password':
                if ($_POST['password']) {
                    $password = $_POST['password'];
                    if ($_POST['channel']) {
                        $channel = $_POST['channel'];
                        $message = array('success' => $db->setChannelPassword($user, $channel, $password));
                    } else {
                        $message = array('success' => $db->setPassword($user, $password));
                    }
                    reply($message);
                } else {
                    reply(array('error' => 'incorrect or empty parameters'), 400);
                }
                break;
            
            case 'description':
                if ($_POST['channel'] && $_POST['description']) {
                    $channel = $_POST['channel'];
                    $description = $_POST['description'];
                    $message = array('success' => $db->setChannelDescription($user, $channel, $description));
                    reply($message);
                } else {
                    reply(array('error' => 'incorrect or empty parameters'), 400);
                }
                break;
            
            case 'channels':
                $message = array('channels' => $db->getChannels($user));
                reply($message);
                break;
                
            case 'join':
                if ($_POST['channel']) {
                    $channel = $_POST['channel'];
                    if ($_POST['password']) {
                        $password = $_POST['password'];
                        $message = array('success' => $db->joinChannel($user, $channel, $password));
                    } else {
                        $message = array('success' => $db->joinChannel($user, $channel));
                    }
                    reply($message);
                } else {
                    reply(array('error' => 'incorrect or empty parameters'), 400);
                }
                break;
            
            case 'leave':
                if ($_POST['channel']) {
                    $channel = $_POST['channel'];
                    $message = array('success' => $db->leaveChannel($user, $channel));
                    reply($message);
                } else {
                    reply(array('error' => 'incorrect or empty parameters'), 400);
                }
                break;
            
            case 'messages':
                if ($_POST['channel']) {
                    $channel = $_POST['channel'];
                    $message = array('messages' => $db->getMessages($user, $channel));
                    reply($message);
                } else {
                    reply(array('error' => 'incorrect or empty parameters'), 400);
                }
                break;
                
            case 'message':
                if ($_POST['channel'] && $_POST['message']) {
                    $channel = $_POST['channel'];
                    $message = $_POST['message'];
                    $message = array('success' => $db->postMessage($user, $channel, $message));
                    reply($message);
                } else {
                    reply(array('error' => 'incorrect or empty parameters'), 400);
                }
                break;
            
            default:
                $message=array('error' => 'no such function available');
                reply($message, 400);
        }
    } else {
        switch ($_GET['function']) {
            case 'login':
                $token = $db->testUser($_POST['username'], $_POST['password']);
                if ($token) {
                    $message=array('token' => $token);
                    reply($message);
                } else {
                    reply(array('error' => 'invalid username or password'), 400);
                }
                break;
            case 'register':
                if (!empty($_POST['username']) && !empty($_POST['password']) && !empty($_POST['nick'])) {
                    $username = $_POST['username'];
                    $password = $_POST['password'];
                    $nick = $_POST['nick'];
                    $message=array('success' => $db->registerUser($nick, $username, $password));
                    reply($message);
                } else {
                    reply(array('error' => 'incorrect or empty parameters'), 400);
                }
                break;
                
            default:
                $message=array('error' => 'no such function available');
                reply($message, 400);
        }
    }       
} else {
    reply(array('message' => 'No payload or wrong format.'));
}

$db->close();

//$test = array('n1' => 'test1', 'n2' => 'test2');


/*
{
"origin":"https://preview.c9users.io",
"username":"yes",
"password":"yes",
"channel":"flax"
}

{"origin":"bloodphoenix.net","muffin":"yes"}

{
"origin":"https://preview.c9users.io",
"username":"gustav",
"password":"gra",
"channel":"flax",
"tokens":"elo"
}

*/

?>