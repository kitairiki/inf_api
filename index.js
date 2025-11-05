import express from "express";
import fs from "fs";
import basicAuth from "basic-auth";

// Expressの初期化
const app = express();
app.use(express.json());
const USERS_FILE = "./users.json";

// ユーザー情報をJSONファイルから読み込む
const readUsers = () => JSON.parse(fs.readFileSync(USERS_FILE));

// ユーザー情報をJSONファイルに書き込む
const writeUsers = (data) =>
  fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));

// Basic認証を行う関数
// リクエストヘッダーから認証情報を取得し、users.jsonと照合する
function auth(req) {
  const credentials = basicAuth(req);
  if (!credentials) return null;
  const users = readUsers();
  const user = users.find(
    (u) => u.user_id === credentials.name && u.password === credentials.pass
  );
  return user || null;
}

// 新規ユーザーアカウントを作成する
app.post("/signup", (req, res) => {
  const { user_id, password } = req.body;
  const users = readUsers();

  // 必須チェック
  if (!user_id || !password) {
    return res.status(400).json({
      message: "Account creation failed",
      cause: "Required user_id and password",
    });
  }

  // 長さチェック
  if (
    user_id.length < 6 ||
    user_id.length > 20 ||
    password.length < 8 ||
    password.length > 20
  ) {
    return res.status(400).json({
      message: "Account creation failed",
      cause: "Input Length is incorrect",
    });
  }

  // 文字種チェック
  const idPattern = /^[A-Za-z0-9]+$/;
  const pwPattern = /^[\x21-\x7E]+$/;
  if (!idPattern.test(user_id) || !pwPattern.test(password)) {
    return res.status(400).json({
      message: "Account creation failed",
      cause: "Incorrect character pattern",
    });
  }

  // 重複チェック
  if (users.some((u) => u.user_id === user_id)) {
    return res.status(400).json({
      message: "Account creation failed",
      cause: "Already same user_id is used",
    });
  }

  // 新規ユーザーを作成して追加
  const newUser = { user_id, password, nickname: user_id, comment: "" };
  users.push(newUser);
  writeUsers(users);

  res.json({
    message: "Account successfully created",
    user: { user_id, nickname: user_id },
  });
});

// 指定されたuser_idのユーザー情報を取得する
app.get("/users/:user_id", (req, res) => {
  const targetId = req.params.user_id;
  const authedUser = auth(req);

  // 認証失敗
  if (!authedUser) {
    return res.status(401).json({ message: "Authentication failed" });
  }

  const users = readUsers();
  const user = users.find((u) => u.user_id === targetId);

  // ユーザーが存在しない
  if (!user) {
    return res.status(404).json({ message: "No user found" });
  }

  const nickname = user.nickname || user.user_id;
  const comment = user.comment || "";

  res.json({
    message: "User details by user_id",
    user: {
      user_id: user.user_id,
      nickname,
      ...(comment ? { comment } : {}),
    },
  });
});

// 指定されたuser_idのユーザー情報を更新する
app.patch("/users/:user_id", (req, res) => {
  const targetId = req.params.user_id;
  const authedUser = auth(req);

  // 認証失敗
  if (!authedUser) {
    return res.status(401).json({ message: "Authentication failed" });
  }

  // 権限チェック
  if (authedUser.user_id !== targetId) {
    return res.status(403).json({ message: "No permission for update" });
  }

  const users = readUsers();
  const userIndex = users.findIndex((u) => u.user_id === targetId);
  if (userIndex === -1) {
    return res.status(404).json({ message: "No user found" });
  }

  const { nickname, comment, user_id, password } = req.body;

  // user_id/passwordの変更は禁止
  if (user_id || password) {
    return res.status(400).json({
      message: "User updation failed",
      cause: "Not updatable user_id and password",
    });
  }

  // 必須チェック
  if (nickname === undefined && comment === undefined) {
    return res.status(400).json({
      message: "User updation failed",
      cause: "Required nickname or comment",
    });
  }

  // 文字数チェック
  if ((nickname && nickname.length > 30) || (comment && comment.length > 100)) {
    return res.status(400).json({
      message: "User updation failed",
      cause: "String length limit exceeded or containing invalid characters",
    });
  }

  // 更新処理
  if (nickname !== undefined) {
    users[userIndex].nickname = nickname === "" ? targetId : nickname;
  }
  if (comment !== undefined) {
    users[userIndex].comment = comment === "" ? "" : comment;
  }

  writeUsers(users);

  res.json({
    message: "User successfully updated",
    user: {
      user_id: users[userIndex].user_id,
      nickname: users[userIndex].nickname,
      comment: users[userIndex].comment,
    },
  });
});

// 認証されたユーザーのアカウントを削除する
app.post("/close", (req, res) => {
  const authedUser = auth(req);
  if (!authedUser) {
    return res.status(401).json({ message: "Authentication failed" });
  }

  const users = readUsers();
  const newUsers = users.filter((u) => u.user_id !== authedUser.user_id);
  writeUsers(newUsers);

  res.json({
    message: "Account and user successfully removed",
  });
});

// サーバーの起動
app.listen(process.env.PORT || 3000, () =>
  console.log("Server running on port 3000")
);
