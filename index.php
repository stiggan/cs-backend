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
                    $message = array('success' => $db->setPassword($user, $password));
                    reply($message);
                } else {
                    reply(array('error' => 'incorrect or empty parameters'), 400);
                }
                break;
                
            case 'messages':
                if ($_POST['channel']) {
                    $message = array('messages' => array(
                        5432422 => array('nick' => 'lennart', 'message' => 'hej'),
                        5443454 => array('nick' => 'bosse', 'message' => 'hej'),
                        5455344 => array('nick' => 'bosse', 'message' => 'vad heter du?'),
                        5468387 => array('nick' => 'lennart', 'message' => 'jag heter lennart'),
                        5475136 => array('nick' => 'bosse', 'message' => '=)')
                    ));
                    reply($message);
                } else {
                    reply(array(), 400);
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