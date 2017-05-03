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
        
        function updateToken($token = false, $user=false) {
            $query = $this->prepare('DELETE FROM sessions WHERE time < :time;');
            $query->bindValue(':time', time()-3600);
            $query->execute();
            if (!$token) {
                do {
                    $token = md5(uniqid(rand(), true));
                    $query = $this->prepare('SELECT token FROM sessions WHERE token = :user;');
                    $query->bindValue(':user', $username);
                    $result = $query->execute();
                } while(!empty($result->fetchArray(SQLITE3_ASSOC)));
                
                $query = $this->prepare('INSERT INTO sessions VALUES(:token, :user, :time);');
                $query->bindValue(':token', $token);
                $query->bindValue(':user', $user);
                $query->bindValue(':time', time());
                $query->execute();
            } else {
                $query = $this->prepare('SELECT token FROM SESSIONS WHERE token = :token;');
                $query->bindValue(':token', $token);
                $result = $query->execute();
                if (empty($result->fetchArray(SQLITE3_ASSOC)))
                    return false;
                $query = $this->prepare('UPDATE sessions SET time = :time WHERE token = :token;');
                $query->bindValue(':token', $token);
                $query->bindValue(':time', time());
                $query->execute();
            }
            return $token;
        }
        
        function getUser($username, $select = '*') {
            $query = $this->prepare('SELECT '.$select.' FROM users WHERE user = :user;');
            $query->bindValue(':user', $username);
            return $query->execute()->fetchArray(SQLITE3_ASSOC);
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
                if ($query->execute()) // fixa
                    return true;
            }
            
            return false;
        }
        
        function changePassword($password) {
            
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