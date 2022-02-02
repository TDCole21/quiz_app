-- Database setup

-- From Windows
-- I created an EC2 instance running Linux, and saved the PEM file in this directory
-- Make sure the EC2 instance is running, then in VSCode terminal, run:
-- ssh -i "quiz-rds.pem" ubuntu@ec2-34-245-51-155.eu-west-1.compute.amazonaws.com
-- Note, when you stop and start the instance, it'll have a different IP address, so this code will need to be altered.
-- Then on the EC2 Linux instance, run the below linux command

-- From Linux
-- mysql -h quiz.cbpf0qmeaxbr.eu-west-1.rds.amazonaws.com -P 3306 -u admin -p
-- PaB98CeB65OaK91


BEGIN;

CREATE DATABASE IF NOT EXISTS Quiz;

USE Quiz;

DROP TABLE IF EXISTS Users, Quiz, Participants, Rounds, Questions, Answers;

CREATE TABLE Users (
    User_ID INT(3) AUTO_INCREMENT NOT NULL PRIMARY KEY,
    Username VARCHAR(50) UNIQUE NOT NULL,
    User_Email VARCHAR(50) UNIQUE NOT NULL,
    User_Password CHAR(225) NOT NULL,
    User_Admin BOOLEAN NOT NULL
    );

CREATE TABLE Quiz (
    Quiz_ID INT(3) AUTO_INCREMENT NOT NULL PRIMARY KEY,
    Quiz_Name VARCHAR(50) UNIQUE NOT NULL,
    Quiz_Description TEXT NOT NULL,
    Active BOOLEAN,
    Completed DATETIME
    );

CREATE TABLE Participants (
    User_ID INT(3) NOT NULL,
    Quiz_ID INT(3) NOT NULL,
    Ready BOOLEAN,
    FOREIGN KEY(User_ID) REFERENCES Users (User_ID) ON DELETE CASCADE,
    FOREIGN KEY(Quiz_ID) REFERENCES Quiz (Quiz_ID) ON DELETE CASCADE
);

CREATE TABLE Rounds (
    Round_ID INT(3) AUTO_INCREMENT NOT NULL PRIMARY KEY,
    Quiz_ID INT(3) NOT NULL,
    Round_Name VARCHAR(50),
    Round_Order INT(3) NOT NULL,
    Round_Description TEXT NOT NULL,
    Active BOOLEAN,
    Completed BOOLEAN,
    FOREIGN KEY(Quiz_ID) REFERENCES Quiz (Quiz_ID) ON DELETE CASCADE
);

CREATE TABLE Questions (
    Question_ID INT(3) AUTO_INCREMENT NOT NULL PRIMARY KEY,
    Round_ID INT(3) NOT NULL,
    Question_Order INT(3) NOT NULL,
    Question TEXT,
    Correct_Answer TEXT,
    Points INT(3),
    Video_url TEXT,
    Image_url TEXT,
    Audio_url TEXT,
    Question_Tag TEXT,
    Active BOOLEAN,
    Completed BOOLEAN,
    FOREIGN KEY(Round_ID) REFERENCES Rounds (Round_ID) ON DELETE CASCADE    
);

CREATE TABLE Answers (
    User_ID INT(3) NOT NULL,
    Question_ID INT(3) NOT NULL,
    Answer TEXT NOT NULL,
    Correct BOOLEAN,
    Timestamp TIMESTAMP,
    FOREIGN KEY(User_ID) REFERENCES Users (User_ID) ON DELETE CASCADE,
    FOREIGN KEY(Question_ID) REFERENCES Questions (Question_ID) ON DELETE CASCADE
);

COMMIT;


-- Turns User 1 into an admin
UPDATE Users SET User_Admin=1 WHERE User_ID=1;