USE login;

CREATE TABLE user_extra_event
(
  user_email VARCHAR(64) NOT NULL,
  origin_extra_event_id VARCHAR(128)
);

CREATE TABLE origin_extra_event
(
  id INT PRIMARY KEY NOT NULL,
  name VARCHAR(128),
  price INT,
  description VARCHAR(1024)
);