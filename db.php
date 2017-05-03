<?php
// Init database

    class MyDB extends SQLite3 {
        function __construct() {
            $this->open('db/cs-data.db');
            $this->initDBTables();
        }
        
        function initDBTables() {
            $this->busyTimeout(5000);
            //$this->exec('PRAGMA journal_mode = wal; PRAGMA foreign_keys = ON;');
            $query = <<<EOF
                PRAGMA journal_mode = wal;
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS users
                    (user VARCHAR(50) PRIMARY KEY       NOT NULL,
                    password    VARCHAR(255)            NOT NULL,
                    nick        TEXT                    NOT NULL);
                
                CREATE TABLE IF NOT EXISTS sessions
                    (token VARCHAR(255) PRIMARY KEY     NOT NULL,
                    user        VARCHAR(50)             NOT NULL,
                    time        INT                     NOT NULL,
                    FOREIGN KEY(user) REFERENCES users(user));
                
                CREATE TABLE IF NOT EXISTS channels
                    (name VARCHAR(50) PRIMARY KEY       NOT NULL,
                    description TEXT                    NOT NULL,
                    password    TEXT                    NOT NULL);
                    
                CREATE TABLE IF NOT EXISTS members
                    (user        VARCHAR(50)     NOT NULL,
                    channel     VARCHAR(50)     NOT NULL,
                    FOREIGN KEY(user) REFERENCES users(user),
                    FOREIGN KEY(channel) REFERENCES channels(name),
                    PRIMARY KEY(user, channel));
                    
                CREATE TABLE IF NOT EXISTS messages
                    (id INT PRIMARY KEY         NOT NULL,
                    user        VARCHAR(50)     NOT NULL,
                    channel     VARCHAR(50)     NOT NULL,
                    message     TEXT            NOT NULL,
                    time        INT             NOT NULL,
                    FOREIGN KEY(user) REFERENCES users(user),
                    FOREIGN KEY(channel) REFERENCES channels(name));
EOF;
            $return = $this->exec($query);
            if(!$return){
                error_log($this->lastErrorMsg());
            }
        }
        
        function getUser($username, $select = '*') {
            $query = $this->prepare('SELECT '.$select.' FROM users WHERE user = :user;');
            $query->bindValue(':user', $username);
            return $query->execute()->fetchArray(SQLITE3_ASSOC);
        }
        
        function getToken($token, $select = '*') {
            $query = $this->prepare('SELECT '.$select.' FROM sessions WHERE token = :token;');
            $query->bindValue(':token', $token);
            return $query->execute()->fetchArray(SQLITE3_ASSOC);
        }
        
        function randomToken() {
            return md5(uniqid(rand(), true));
        }
        
        function cleanTokens($user = false) {
            $query = $this->prepare('DELETE FROM sessions WHERE time < :time;');
            if ($user) {
                $query = $this->prepare('DELETE FROM sessions WHERE time < :time OR user = :user;');
                $query->bindValue(':user', $user);
            }
            $query->bindValue(':time', time()-3600);
            $query->execute();
        }
        
        function updateToken($token = false, $user=false) {
            $this->cleanTokens();
            if (!$token) {
                do {
                    $token = $this->randomToken();
                } while(!empty($this->getToken($token)));
                
                $query = $this->prepare('INSERT INTO sessions VALUES(:token, :user, :time);');
                $query->bindValue(':token', $token);
                $query->bindValue(':user', $user);
                $query->bindValue(':time', time());
                $query->execute();
            } else {
                if (empty($this->getToken($token, 'token')))
                    return false;
                $query = $this->prepare('UPDATE sessions SET time = :time WHERE token = :token;');
                $query->bindValue(':token', $token);
                $query->bindValue(':time', time());
                $query->execute();
            }
            return $token;
        }
        

        function testUser($username, $password) {
            $result = $this->getUser($username, 'password');
            if (isset($result['password']) && password_verify($password, $result['password'])) {
                return $this->updateToken(false, $username);
            }

            return false;    
        }
        
        function registerUser($nick, $username, $password) {
            if (empty($this->getUser($username))) {
                $query = $this->prepare('INSERT INTO users VALUES(:user, :pass, :nick);');
                $query->bindValue(':user', $username);
                $query->bindValue(':pass', password_hash($password, PASSWORD_DEFAULT));
                $query->bindValue(':nick', $nick);
                if ($query->execute())
                    return true;
            }
            
            return false;
        }
        
        function setNick($username, $nick) {
            if (!empty($this->getUser($username))) {
                $query = $this->prepare('UPDATE users SET nick = :nick WHERE user = :user;');
                $query->bindValue(':user', $username);
                $query->bindValue(':nick', $nick);
                if ($query->execute())
                    return true;
            }
            return false;
        }
        
        function getNick($username) {
            $result = $this->getUser($username);
            if (!empty($result)) {
                return $result['nick'];
            }
            return false;
        }
        
        function setPassword($username, $password) {
            if (!empty($this->getUser($username))) {
                $query = $this->prepare('UPDATE users SET password = :password WHERE user = :user;');
                $query->bindValue(':user', $username);
                $query->bindValue(':password', password_hash($password, PASSWORD_DEFAULT));
                if ($query->execute()) {
                    $this->cleanTokens($username);
                    return true;
                }
            }
            return false;
        }
        
        function createChannel($channel) {
            $query = $this->prepare('SELECT * FROM channels WHERE channel = :channel;');
            $query->bindValue(':channel', $channel);
            if (empty($query->execute()->fetchArray(SQLITE3_ASSOC))) {
                $query = $this->prepare('INSERT INTO channels VALUES(:channel, :desc, :pass);');
                $query->bindValue(':channel', $channel);
                $query->bindValue(':desc', '');
                $query->bindValue(':pass', password_hash('', PASSWORD_DEFAULT));
                if ($query->execute()) // fixa
                    return true;
            }
            return false;
        }
        
        function setChannelPassword($channel, $password) {
            $query = $this->prepare('SELECT * FROM channels WHERE channel = :channel;');
            $query->bindValue(':channel', $channel);
            if (!empty($query->execute()->fetchArray(SQLITE3_ASSOC))) {
                $query = $this->prepare('UPDATE channels SET password = :password WHERE channel = :channel;');
                $query->bindValue(':channel', $channel);
                $query->bindValue(':pass', password_hash($password, PASSWORD_DEFAULT));
                if ($query->execute()) // fixa
                    return true;
            }
            return false;
        }
        
        function setChannelDescription($channel, $description) {
            $query = $this->prepare('SELECT * FROM channels WHERE channel = :channel;');
            $query->bindValue(':channel', $channel);
            if (!empty($query->execute()->fetchArray(SQLITE3_ASSOC))) {
                $query = $this->prepare('UPDATE channels SET description = :desc WHERE channel = :channel;');
                $query->bindValue(':channel', $channel);
                $query->bindValue(':desc', $description);
                if ($query->execute()) // fixa
                    return true;
            }
            return false;
        }
        
        function joinChannel($channel, $username, $password = '') {
            $query = $this->prepare('SELECT * FROM channels WHERE channel = :channel;');
            $query->bindValue(':channel', $channel);
            $result = $query->execute()->fetchArray(SQLITE3_ASSOC);
            if (empty($result)) {
                createChannel($channel);
            } else {
                if (!password_verify($password, $result['password']))
                    return false;
            }
            $query = $this->prepare('INSERT INTO members VALUES(:channel, "", );');
            $query->bindValue(':channel', $channel);
            if ($query->execute()) // fixa
                return true;
            return false;
        }
        
        
        function validateToken($token) {
            if ($this->updateToken($token))
                return true;
            return false;
        }
    }
?>