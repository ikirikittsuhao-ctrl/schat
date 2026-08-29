require("dotenv").config();

const express = require("express");
const http = require("http");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const { Server } = require("socket.io");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const server = http.createServer(app);

const PORT =
  Number(process.env.PORT || 3000);

const isProduction =
  process.env.NODE_ENV === "production";

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN ||
  `http://localhost:${PORT}`;

if (
  !process.env.SUPABASE_URL ||
  !process.env.SUPABASE_SERVICE_ROLE_KEY
) {
  console.error(
    "SUPABASE_URL と SUPABASE_SERVICE_ROLE_KEY が必要です。"
  );

  process.exit(1);
}

if (
  !process.env.JWT_SECRET ||
  process.env.JWT_SECRET.length < 32
) {
  console.error(
    "JWT_SECRET は32文字以上のランダム文字列を設定してください。"
  );

  process.exit(1);
}

const supabase =
  createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY,
    {
      auth:{
        autoRefreshToken:false,
        persistSession:false
      }
    }
  );

const io =
  new Server(
    server,
    {
      cors:{
        origin:FRONTEND_ORIGIN,
        credentials:true
      },
      transports:[
        "websocket",
        "polling"
      ]
    }
  );

app.set(
  "trust proxy",
  1
);

app.disable(
  "x-powered-by"
);

app.use(
  helmet({
    contentSecurityPolicy:{
      directives:{
        defaultSrc:["'self'"],

        styleSrc:[
          "'self'",
          "'unsafe-inline'",
          "https://cdnjs.cloudflare.com",
          "https://fonts.googleapis.com"
        ],

        fontSrc:[
          "'self'",
          "https://cdnjs.cloudflare.com",
          "https://fonts.gstatic.com",
          "data:"
        ],

        scriptSrc:[
          "'self'",
          "'unsafe-inline'",
          "https://cdnjs.cloudflare.com",
          "https://unpkg.com"
        ],

        scriptSrcAttr:[
          "'unsafe-inline'"
        ],

        imgSrc:[
          "'self'",
          "data:",
          "blob:",
          "https:"
        ],

        connectSrc:[
          "'self'",
          "ws:",
          "wss:"
        ],

        camera:[
          "'self'"
        ],

        objectSrc:[
          "'none'"
        ],

        baseUri:[
          "'self'"
        ],

        frameAncestors:[
          "'none'"
        ]
      }
    },

    referrerPolicy:{
      policy:
        "strict-origin-when-cross-origin"
    }
  })
);

app.use(
  cors({
    origin:FRONTEND_ORIGIN,
    credentials:true,
    methods:[
      "GET",
      "POST",
      "PUT",
      "DELETE",
      "OPTIONS"
    ]
  })
);

app.use(
  express.json({
    limit:"32kb"
  })
);

app.use(
  cookieParser()
);

const authLimiter =
  rateLimit({
    windowMs:
      15*60*1000,

    limit:20,

    standardHeaders:"draft-8",

    legacyHeaders:false,

    message:{
      error:
        "認証試行が多すぎます。しばらく待ってください。"
    }
  });

const apiLimiter =
  rateLimit({
    windowMs:
      60*1000,

    limit:180,

    standardHeaders:"draft-8",

    legacyHeaders:false,

    message:{
      error:
        "リクエストが多すぎます。"
    }
  });

app.use(
  "/api",
  apiLimiter
);

app.use(
  "/api/auth",
  authLimiter
);

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    ),
    {
      extensions:["html"],
      index:"index.html"
    }
  )
);

function normalizeUsername(value){

  return String(
    value || ""
  )
    .trim()
    .toLowerCase();
}

function validUsername(username){

  return /^[a-zA-Z0-9_]{3,24}$/
    .test(username);
}

function validDisplayName(name){

  const value=
    String(name || "")
      .trim();

  return (
    value.length>=1 &&
    value.length<=40
  );
}

function safeText(
  value,
  max=2000
){

  return String(
    value || ""
  )
    .trim()
    .slice(0,max);
}

function signToken(user){

  return jwt.sign(
    {
      sub:user.id,
      username:user.username
    },
    process.env.JWT_SECRET,
    {
      expiresIn:
        process.env.JWT_EXPIRES_IN ||
        "7d",

      issuer:"schat"
    }
  );
}

function setAuthCookie(
  res,
  token
){

  res.cookie(
    "schat_token",
    token,
    {
      httpOnly:true,
      secure:isProduction,
      sameSite:
        isProduction
          ? "none"
          : "lax",

      maxAge:
        7*24*60*60*1000,

      path:"/"
    }
  );
}

function clearAuthCookie(res){

  res.clearCookie(
    "schat_token",
    {
      httpOnly:true,
      secure:isProduction,

      sameSite:
        isProduction
          ? "none"
          : "lax",

      path:"/"
    }
  );
}

async function getUserById(id){

  const {
    data,
    error
  } =
    await supabase
      .from("users")
      .select(
        "id, username, display_name, created_at"
      )
      .eq(
        "id",
        id
      )
      .maybeSingle();

  if(error){
    throw error;
  }

  return data;
}

async function requireAuth(
  req,
  res,
  next
){

  try{

    const token=
      req.cookies.schat_token;

    if(!token){

      return res
        .status(401)
        .json({
          error:
            "ログインが必要です。"
        });
    }

    const payload=
      jwt.verify(
        token,
        process.env.JWT_SECRET,
        {
          issuer:"schat"
        }
      );

    const user=
      await getUserById(
        payload.sub
      );

    if(!user){

      return res
        .status(401)
        .json({
          error:
            "ユーザーが存在しません。"
        });
    }

    req.user=user;

    next();

  }catch{

    return res
      .status(401)
      .json({
        error:
          "認証情報が無効です。"
      });
  }
}

function getSocketUser(socket){

  return socket.data.user;
}

async function authenticateSocket(
  socket,
  next
){

  try{

    const cookieHeader=
      socket.handshake
        .headers
        .cookie ||
      "";

    const match=
      cookieHeader.match(
        /(?:^|;\s*)schat_token=([^;]+)/
      );

    if(!match){

      return next(
        new Error(
          "UNAUTHORIZED"
        )
      );
    }

    const token=
      decodeURIComponent(
        match[1]
      );

    const payload=
      jwt.verify(
        token,
        process.env.JWT_SECRET,
        {
          issuer:"schat"
        }
      );

    const user=
      await getUserById(
        payload.sub
      );

    if(!user){

      return next(
        new Error(
          "UNAUTHORIZED"
        )
      );
    }

    socket.data.user=
      user;

    next();

  }catch{

    next(
      new Error(
        "UNAUTHORIZED"
      )
    );
  }
}

async function isRoomMember(
  userId,
  roomId
){

  const {
    data,
    error
  } =
    await supabase
      .from("room_members")
      .select("room_id")
      .eq(
        "room_id",
        roomId
      )
      .eq(
        "user_id",
        userId
      )
      .maybeSingle();

  if(error){
    throw error;
  }

  return !!data;
}

async function getRoom(roomId){

  const {
    data,
    error
  } =
    await supabase
      .from("rooms")
      .select(
        "id, name, type, owner_id, created_at, updated_at"
      )
      .eq(
        "id",
        roomId
      )
      .maybeSingle();

  if(error){
    throw error;
  }

  return data;
}

async function getRoomsForUser(
  userId
){

  const {
    data,
    error
  } =
    await supabase
      .from("room_members")
      .select(`
        room_id,
        rooms:room_id (
          id,
          name,
          type,
          owner_id,
          created_at,
          updated_at
        )
      `)
      .eq(
        "user_id",
        userId
      );

  if(error){
    throw error;
  }

  const roomList = (data || []).map(x => x.rooms).filter(Boolean);

  for (let r of roomList) {
    if (r.type === "friend") {
      const { data: members } = await supabase
        .from("room_members")
        .select("user_id, users:user_id(id, username, display_name)")
        .eq("room_id", r.id);

      const other = (members || []).map(m => m.users).find(u => u && u.id !== userId);
      if (other) {
        r.name = other.display_name;
      }
    }
  }

  return roomList.sort(
    (a,b)=>
      new Date(
        b.updated_at
      )-
      new Date(
        a.updated_at
      )
  );
}

async function getContacts(
  userId
){

  const {
    data,
    error
  } =
    await supabase
      .from("friendships")
      .select(`
        id,
        friend_id,
        status,
        friend:friend_id (
          id,
          username,
          display_name
        )
      `)
      .eq(
        "user_id",
        userId
      )
      .eq(
        "status",
        "accepted"
      );

  if(error){
    throw error;
  }

  return data || [];
}

/* =========================
   招待関係
========================= */

async function getPendingInvites(
  userId
){

  const {
    data,
    error
  } =
    await supabase
      .from("room_invites")
      .select(`
        id,
        room_id,
        inviter_id,
        invitee_id,
        status,
        created_at,
        room:room_id (
          id,
          name,
          type,
          owner_id,
          created_at,
          updated_at
        ),
        inviter:inviter_id (
          id,
          username,
          display_name
        )
      `)
      .eq(
        "invitee_id",
        userId
      )
      .eq(
        "status",
        "pending"
      )
      .order(
        "created_at",
        {
          ascending:false
        }
      );

  if(error){
    throw error;
  }

  return data || [];
}

async function emitInviteToUser(
  userId,
  inviteId
){

  const {
    data,
    error
  } =
    await supabase
      .from("room_invites")
      .select(`
        id,
        room_id,
        inviter_id,
        invitee_id,
        status,
        created_at,
        room:room_id (
          id,
          name,
          type,
          owner_id,
          created_at,
          updated_at
        ),
        inviter:inviter_id (
          id,
          username,
          display_name
        )
      `)
      .eq(
        "id",
        inviteId
      )
      .maybeSingle();

  if(error){
    throw error;
  }

  if(!data){
    return;
  }

  io.to(
    `user:${userId}`
  ).emit(
    "invite:new",
    data
  );
}

/* =========================
   Health
========================= */

app.get(
  "/api/health",
  (req,res)=>{
    res.json({
      ok:true,
      service:"schat",
      time:
        new Date().toISOString()
    });
  }
);

/* =========================
   Auth
========================= */

app.post(
  "/api/auth/register",
  async(req,res)=>{

    try{

      const username=
        normalizeUsername(
          req.body.username
        );

      const password=
        String(
          req.body.password || ""
        );

      const displayName=
        String(
          req.body.displayName ||
          username
        ).trim();

      if(!validUsername(username)){

        return res
          .status(400)
          .json({
            error:
              "ユーザー名は英数字と _ の3〜24文字で入力してください。"
          });
      }

      if(
        password.length<8 ||
        password.length>128
      ){

        return res
          .status(400)
          .json({
            error:
              "パスワードは8〜128文字にしてください。"
          });
      }

      if(
        !validDisplayName(
          displayName
        )
      ){

        return res
          .status(400)
          .json({
            error:
              "表示名は1〜40文字です。"
          });
      }

      const {
        data:existing,
        error:existingError
      } =
        await supabase
          .from("users")
          .select("id")
          .eq(
            "username",
            username
          )
          .maybeSingle();

      if(existingError){
        throw existingError;
      }

      if(existing){

        return res
          .status(409)
          .json({
            error:
              "そのユーザー名は既に使用されています。"
          });
      }

      const passwordHash=
        await bcrypt.hash(
          password,
          12
        );

      const {
        data:user,
        error
      } =
        await supabase
          .from("users")
          .insert({
            username,
            display_name:
              displayName,
            password_hash:
              passwordHash
          })
          .select(
            "id, username, display_name, created_at"
          )
          .single();

      if(error){

        if(
          error.code==="23505"
        ){

          return res
            .status(409)
            .json({
              error:
                "そのユーザー名は既に使用されています。"
            });
        }

        throw error;
      }

      setAuthCookie(
        res,
        signToken(user)
      );

      res
        .status(201)
        .json({
          user
        });

    }catch(error){

      console.error(
        "register:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "アカウント作成に失敗しました。"
        });
    }
  }
);

app.post(
  "/api/auth/login",
  async(req,res)=>{

    try{

      const username=
        normalizeUsername(
          req.body.username
        );

      const password=
        String(
          req.body.password || ""
        );

      if(
        !validUsername(username) ||
        !password
      ){

        return res
          .status(400)
          .json({
            error:
              "ユーザー名とパスワードを入力してください。"
          });
      }

      const {
        data:user,
        error
      } =
        await supabase
          .from("users")
          .select(
            "id, username, display_name, password_hash, created_at"
          )
          .eq(
            "username",
            username
          )
          .maybeSingle();

      if(error){
        throw error;
      }

      const valid=
        user
          ? await bcrypt.compare(
              password,
              user.password_hash
            )
          : false;

      if(!valid){

        return res
          .status(401)
          .json({
            error:
              "ユーザー名またはパスワードが違います。"
          });
      }

      delete user.password_hash;

      setAuthCookie(
        res,
        signToken(user)
      );

      res.json({
        user
      });

    }catch(error){

      console.error(
        "login:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "ログインに失敗しました。"
        });
    }
  }
);

app.post(
  "/api/auth/logout",
  (req,res)=>{

    clearAuthCookie(res);

    res.json({
      ok:true
    });
  }
);

app.get(
  "/api/auth/me",
  requireAuth,
  (req,res)=>{

    res.json({
      user:req.user
    });
  }
);

/* =========================
   Profile
========================= */

app.put(
  "/api/me",
  requireAuth,
  async(req,res)=>{

    try{

      const displayName=
        String(
          req.body.displayName ||
          ""
        ).trim();

      if(
        !validDisplayName(
          displayName
        )
      ){

        return res
          .status(400)
          .json({
            error:
              "表示名は1〜40文字です。"
          });
      }

      const {
        data,
        error
      } =
        await supabase
          .from("users")
          .update({
            display_name:
              displayName
          })
          .eq(
            "id",
            req.user.id
          )
          .select(
            "id, username, display_name, created_at"
          )
          .single();

      if(error){
        throw error;
      }

      res.json({
        user:data
      });

    }catch(error){

      console.error(
        "profile:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "プロフィール更新に失敗しました。"
        });
    }
  }
);

/* =========================
   Rooms
========================= */

app.get(
  "/api/rooms",
  requireAuth,
  async(req,res)=>{

    try{

      res.json(
        await getRoomsForUser(
          req.user.id
        )
      );

    }catch(error){

      console.error(
        "rooms:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "ルーム取得に失敗しました。"
        });
    }
  }
);

app.get(
  "/api/rooms/:roomId",
  requireAuth,
  async(req,res)=>{

    try{

      const room=
        await getRoom(
          req.params.roomId
        );

      if(!room){

        return res
          .status(404)
          .json({
            error:
              "ルームが見つかりません。"
          });
      }

      if(
        !(await isRoomMember(
          req.user.id,
          room.id
        ))
      ){

        return res
          .status(403)
          .json({
            error:
              "このルームへのアクセス権がありません。"
          });
      }

      if (room.type === "friend") {
        const { data: members } = await supabase
          .from("room_members")
          .select("user_id, users:user_id(id, username, display_name)")
          .eq("room_id", room.id);

        const other = (members || []).map(m => m.users).find(u => u && u.id !== req.user.id);
        if (other) {
          room.name = other.display_name;
        }
      }

      res.json(room);

    }catch(error){

      console.error(
        "room:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "ルーム取得に失敗しました。"
        });
    }
  }
);

app.post(
  "/api/rooms",
  requireAuth,
  async(req,res)=>{

    try{

      const name=
        safeText(
          req.body.name,
          80
        );

      if(!name){

        return res
          .status(400)
          .json({
            error:
              "グループ名を入力してください。"
          });
      }

      const {
        data:room,
        error:roomError
      } =
        await supabase
          .from("rooms")
          .insert({
            name,
            type:"group",
            owner_id:req.user.id
          })
          .select(
            "id, name, type, owner_id, created_at, updated_at"
          )
          .single();

      if(roomError){
        throw roomError;
      }

      const {
        error:memberError
      } =
        await supabase
          .from("room_members")
          .insert({
            room_id:room.id,
            user_id:req.user.id,
            role:"owner"
          });

      if(memberError){
        throw memberError;
      }

      io.emit(
        "rooms:changed"
      );

      res
        .status(201)
        .json(room);

    }catch(error){

      console.error(
        "create room:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "グループ作成に失敗しました。"
        });
    }
  }
);

/* =========================
   Messages
========================= */

app.get(
  "/api/rooms/:roomId/messages",
  requireAuth,
  async(req,res)=>{

    try{

      const roomId=
        req.params.roomId;

      if(
        !(await isRoomMember(
          req.user.id,
          roomId
        ))
      ){

        return res
          .status(403)
          .json({
            error:
              "このルームへのアクセス権がありません。"
          });
      }

      const {
        data,
        error
      } =
        await supabase
          .from("messages")
          .select(
            "id, room_id, sender_id, text, created_at"
          )
          .eq(
            "room_id",
            roomId
          )
          .order(
            "created_at",
            {
              ascending:true
            }
          )
          .limit(300);

      if(error){
        throw error;
      }

      res.json(
        data || []
      );

    }catch(error){

      console.error(
        "messages:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "メッセージ取得に失敗しました。"
        });
    }
  }
);

app.post(
  "/api/rooms/:roomId/messages",
  requireAuth,
  async(req,res)=>{

    try{

      const roomId=
        req.params.roomId;

      const text=
        safeText(
          req.body.text,
          2000
        );

      if(!text){

        return res
          .status(400)
          .json({
            error:
              "メッセージを入力してください。"
          });
      }

      if(
        !(await isRoomMember(
          req.user.id,
          roomId
        ))
      ){

        return res
          .status(403)
          .json({
            error:
              "このルームへのアクセス権がありません。"
          });
      }

      const {
        data:message,
        error
      } =
        await supabase
          .from("messages")
          .insert({
            room_id:roomId,
            sender_id:req.user.id,
            text
          })
          .select(
            "id, room_id, sender_id, text, created_at"
          )
          .single();

      if(error){
        throw error;
      }

      await supabase
        .from("rooms")
        .update({
          updated_at:
            new Date()
              .toISOString()
        })
        .eq(
          "id",
          roomId
        );

      io.to(
        `room:${roomId}`
      ).emit(
        "message:new",
        message
      );

      io.emit(
        "rooms:changed"
      );

      res
        .status(201)
        .json(message);

    }catch(error){

      console.error(
        "send message:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "メッセージ送信に失敗しました。"
        });
    }
  }
);

/* =========================
   Friends
========================= */

app.get(
  "/api/friends",
  requireAuth,
  async(req,res)=>{

    try{

      res.json(
        await getContacts(
          req.user.id
        )
      );

    }catch(error){

      console.error(
        "friends:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "フレンド取得に失敗しました。"
        });
    }
  }
);

app.get(
  "/api/friends/requests",
  requireAuth,
  async(req,res)=>{

    try{

      const { data, error } = await supabase
        .from("friendships")
        .select(`
          user_id,
          created_at,
          user:user_id (
            id,
            username,
            display_name
          )
        `)
        .eq("friend_id", req.user.id)
        .eq("status", "pending");

      if (error) throw error;
      res.json(data || []);

    }catch(error){

      console.error(
        "friend requests:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "フレンド申請の取得に失敗しました。"
        });
    }
  }
);

async function createFriendshipPair(
  a,
  b
){

  const rows=[
    {
      user_id:a,
      friend_id:b,
      status:"accepted"
    },
    {
      user_id:b,
      friend_id:a,
      status:"accepted"
    }
  ];

  const {
    error
  } =
    await supabase
      .from("friendships")
      .upsert(
        rows,
        {
          onConflict:
            "user_id,friend_id"
        }
      );

  if(error){
    throw error;
  }
}

async function findFriendRoom(
  userA,
  userB
){

  const {
    data,
    error
  } =
    await supabase
      .from("room_members")
      .select(
        "room_id, rooms:room_id(id,name,type,owner_id,created_at,updated_at)"
      )
      .eq(
        "user_id",
        userA
      );

  if(error){
    throw error;
  }

  for(
    const item of data || []
  ){

    const candidate=
      item.rooms;

    if(
      !candidate ||
      candidate.type!=="friend"
    ){
      continue;
    }

    const {
      data:members
    } =
      await supabase
        .from("room_members")
        .select("user_id")
        .eq(
          "room_id",
          candidate.id
        );

    const ids=
      (members || [])
        .map(
          m=>m.user_id
        )
        .sort();

    const targetIds=[
      userA,
      userB
    ].sort();

    if(
      ids.length===2 &&
      ids[0]===targetIds[0] &&
      ids[1]===targetIds[1]
    ){

      return candidate;
    }
  }

  return null;
}

async function ensureFriendRoom(
  userId,
  friend
){

  let room=
    await findFriendRoom(
      userId,
      friend.id
    );

  if(room){
    return room;
  }

  const {
    data:newRoom,
    error:newRoomError
  } =
    await supabase
      .from("rooms")
      .insert({
        name:
          friend.display_name,
        type:"friend",
        owner_id:userId
      })
      .select(
        "id, name, type, owner_id, created_at, updated_at"
      )
      .single();

  if(newRoomError){
    throw newRoomError;
  }

  room=newRoom;

  const {
    error:membersError
  } =
    await supabase
      .from("room_members")
      .insert([
        {
          room_id:room.id,
          user_id:userId,
          role:"member"
        },
        {
          room_id:room.id,
          user_id:friend.id,
          role:"member"
        }
      ]);

  if(membersError){
    throw membersError;
  }

  return room;
}

app.post(
  "/api/friends/add",
  requireAuth,
  async(req,res)=>{

    try{

      const username=
        normalizeUsername(
          req.body.username
        );

      if(
        !validUsername(
          username
        )
      ){

        return res
          .status(400)
          .json({
            error:
              "有効なユーザー名を入力してください。"
          });
      }

      const {
        data:friend,
        error
      } =
        await supabase
          .from("users")
          .select(
            "id, username, display_name"
          )
          .eq(
            "username",
            username
          )
          .maybeSingle();

      if(error){
        throw error;
      }

      if(!friend){

        return res
          .status(404)
          .json({
            error:
              "ユーザーが見つかりません。"
          });
      }

      if(
        friend.id===req.user.id
      ){

        return res
          .status(400)
          .json({
            error:
              "自分自身は追加できません。"
          });
      }

      const { data: existingRel } = await supabase
        .from("friendships")
        .select("status")
        .eq("user_id", req.user.id)
        .eq("friend_id", friend.id)
        .maybeSingle();

      if (existingRel) {
        if (existingRel.status === "accepted") {
          return res.status(400).json({ error: "すでにフレンドです。" });
        } else if (existingRel.status === "pending") {
          return res.status(400).json({ error: "すでにフレンド申請を送信済みです。" });
        }
      }

      const { error: reqError } = await supabase
        .from("friendships")
        .insert({
          user_id: req.user.id,
          friend_id: friend.id,
          status: "pending"
        });

      if (reqError) throw reqError;

      io.to(`user:${friend.id}`).emit("friend:request", {
        from: req.user
      });

      res.status(201).json({
        ok: true,
        message: "フレンド申請を送信しました。"
      });

    }catch(error){

      console.error(
        "add friend:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "フレンド追加に失敗しました。"
        });
    }
  }
);

app.post(
  "/api/friends/accept",
  requireAuth,
  async(req,res)=>{

    try{

      const requesterId = req.body.requesterId;

      if (!requesterId) {
        return res.status(400).json({ error: "申請IDが必要です。" });
      }

      const requester = await getUserById(requesterId);
      if (!requester) {
        return res.status(404).json({ error: "ユーザーが見つかりません。" });
      }

      await createFriendshipPair(req.user.id, requesterId);

      const room = await ensureFriendRoom(req.user.id, requester);

      io.to(`user:${requesterId}`).emit("friend:new", {
        friend: req.user,
        room
      });

      io.to(`user:${req.user.id}`).emit("friend:new", {
        friend: requester,
        room
      });

      res.json({
        ok: true,
        friend: requester,
        room
      });

    }catch(error){

      console.error(
        "accept friend:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "フレンド承認に失敗しました。"
        });
    }
  }
);

app.post(
  "/api/friends/reject",
  requireAuth,
  async(req,res)=>{

    try{

      const requesterId = req.body.requesterId;

      if (!requesterId) {
        return res.status(400).json({ error: "申請IDが必要です。" });
      }

      const { error } = await supabase
        .from("friendships")
        .delete()
        .eq("user_id", requesterId)
        .eq("friend_id", req.user.id)
        .eq("status", "pending");

      if (error) throw error;

      res.json({ ok: true });

    }catch(error){

      console.error(
        "reject friend:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "フレンド拒否に失敗しました。"
        });
    }
  }
);

/* =========================
   QR Friend
========================= */

app.post(
  "/api/friends/qr",
  requireAuth,
  async(req,res)=>{

    try{

      const token=
        safeText(
          req.body.token,
          2000
        );

      if(!token){

        return res
          .status(400)
          .json({
            error:
              "QRデータがありません。"
          });
      }

      const payload=
        jwt.verify(
          token,
          process.env.JWT_SECRET,
          {
            issuer:"schat-qr"
          }
        );

      if(
        payload.type!=="friend_qr" ||
        !payload.sub
      ){

        return res
          .status(400)
          .json({
            error:
              "無効なQRコードです。"
          });
      }

      const friend=
        await getUserById(
          payload.sub
        );

      if(!friend){

        return res
          .status(404)
          .json({
            error:
              "ユーザーが見つかりません。"
          });
      }

      if(
        friend.id===req.user.id
      ){

        return res
          .status(400)
          .json({
            error:
              "自分のQRコードは追加できません。"
          });
      }

      const existing=
        await findFriendRoom(
          req.user.id,
          friend.id
        );

      if (existing) {
        return res.status(200).json({
          friend,
          room: existing,
          alreadyFriend: true,
          message: "すでにフレンドです。"
        });
      }

      await createFriendshipPair(
        req.user.id,
        friend.id
      );

      const room=
        await ensureFriendRoom(
          req.user.id,
          friend
        );

      io.to(
        `user:${friend.id}`
      ).emit(
        "rooms:changed"
      );

      io.to(
        `user:${friend.id}`
      ).emit(
        "friend:new",
        {
          friend:req.user,
          room
        }
      );

      io.to(
        `user:${req.user.id}`
      ).emit(
        "rooms:changed"
      );

      res
        .status(201)
        .json({
          friend,
          room,
          alreadyFriend:false,
          message: "フレンドを追加しました。"
        });

    }catch(error){

      if(
        error.name==="TokenExpiredError" ||
        error.name==="JsonWebTokenError"
      ){

        return res
          .status(400)
          .json({
            error:
              "QRコードが無効または期限切れです。"
          });
      }

      console.error(
        "qr friend:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "QRからのフレンド追加に失敗しました。"
        });
    }
  }
);

app.get(
  "/api/friends/qr",
  requireAuth,
  (req,res)=>{

    const token=
      jwt.sign(
        {
          sub:req.user.id,
          type:"friend_qr",
          nonce:
            crypto.randomUUID()
        },
        process.env.JWT_SECRET,
        {
          issuer:"schat-qr",
          expiresIn:"10m"
        }
      );

    res.json({
      token
    });
  }
);

app.delete(
  "/api/friends/:friendId",
  requireAuth,
  async(req,res)=>{

    try{

      const friendId=
        req.params.friendId;

      const {
        error
      } =
        await supabase
          .from("friendships")
          .delete()
          .or(
            `and(user_id.eq.${req.user.id},friend_id.eq.${friendId}),and(user_id.eq.${friendId},friend_id.eq.${req.user.id})`
          );

      if(error){
        throw error;
      }

      io.to(
        `user:${req.user.id}`
      ).emit(
        "rooms:changed"
      );

      io.to(
        `user:${friendId}`
      ).emit(
        "rooms:changed"
      );

      res.json({
        ok:true
      });

    }catch(error){

      console.error(
        "delete friend:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "フレンド削除に失敗しました。"
        });
    }
  }
);

/* =========================
   Group Member
========================= */

app.post(
  "/api/rooms/:roomId/members",
  requireAuth,
  async(req,res)=>{

    try{

      const roomId=
        req.params.roomId;

      const username=
        normalizeUsername(
          req.body.username
        );

      const room=
        await getRoom(
          roomId
        );

      if(
        !room ||
        room.type!=="group"
      ){

        return res
          .status(404)
          .json({
            error:
              "グループが見つかりません。"
          });
      }

      if(
        room.owner_id!==
        req.user.id
      ){

        return res
          .status(403)
          .json({
            error:
              "グループ管理者のみ追加できます。"
          });
      }

      const {
        data:target,
        error:targetError
      } =
        await supabase
          .from("users")
          .select(
            "id,username,display_name"
          )
          .eq(
            "username",
            username
          )
          .maybeSingle();

      if(targetError){
        throw targetError;
      }

      if(!target){

        return res
          .status(404)
          .json({
            error:
              "ユーザーが見つかりません。"
          });
      }

      const {
        error
      } =
        await supabase
          .from("room_members")
          .upsert(
            {
              room_id:roomId,
              user_id:target.id,
              role:"member"
            },
            {
              onConflict:
                "room_id,user_id"
            }
          );

      if(error){
        throw error;
      }

      io.to(
        `room:${roomId}`
      ).emit(
        "room:changed",
        {
          roomId
        }
      );

      io.to(
        `user:${target.id}`
      ).emit(
        "rooms:changed"
      );

      res.json({
        ok:true,
        user:target
      });

    }catch(error){

      console.error(
        "group member:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "メンバー追加に失敗しました。"
        });
    }
  }
);

/* =========================
   Group Invitations
========================= */

app.get(
  "/api/invites",
  requireAuth,
  async(req,res)=>{

    try{

      const invites=
        await getPendingInvites(
          req.user.id
        );

      res.json(
        invites
      );

    }catch(error){

      console.error(
        "get invites:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "招待状の取得に失敗しました。"
        });
    }
  }
);

app.post(
  "/api/rooms/:roomId/invites",
  requireAuth,
  async(req,res)=>{

    try{

      const roomId=
        req.params.roomId;

      const username=
        normalizeUsername(
          req.body.username
        );

      if(
        !validUsername(
          username
        )
      ){

        return res
          .status(400)
          .json({
            error:
              "有効なユーザー名を入力してください。"
          });
      }

      const room=
        await getRoom(
          roomId
        );

      if(!room){

        return res
          .status(404)
          .json({
            error:
              "グループが見つかりません。"
          });
      }

      if(
        room.type!=="group"
      ){

        return res
          .status(400)
          .json({
            error:
              "グループにのみ招待できます。"
          });
      }

      if(
        !(await isRoomMember(
          req.user.id,
          roomId
        ))
      ){

        return res
          .status(403)
          .json({
            error:
              "このグループのメンバーではありません。"
          });
      }

      const {
        data:target,
        error:targetError
      } =
        await supabase
          .from("users")
          .select(
            "id,username,display_name"
          )
          .eq(
            "username",
            username
          )
          .maybeSingle();

      if(targetError){
        throw targetError;
      }

      if(!target){

        return res
          .status(404)
          .json({
            error:
              "ユーザーが見つかりません。"
          });
      }

      if(
        target.id===req.user.id
      ){

        return res
          .status(400)
          .json({
            error:
              "自分自身には招待できません。"
          });
      }

      if(
        await isRoomMember(
          target.id,
          roomId
        )
      ){

        return res
          .status(409)
          .json({
            error:
              "このユーザーは既にグループのメンバーです。"
          });
      }

      const {
        data:existingInvite,
        error:existingError
      } =
        await supabase
          .from("room_invites")
          .select("id,status")
          .eq(
            "room_id",
            roomId
          )
          .eq(
            "invitee_id",
            target.id
          )
          .eq(
            "status",
            "pending"
          )
          .maybeSingle();

      if(existingError){
        throw existingError;
      }

      if(existingInvite){

        return res
          .status(409)
          .json({
            error:
              "このユーザーには既に招待状を送っています。"
          });
      }

      const {
        data:invite,
        error
      } =
        await supabase
          .from("room_invites")
          .insert({
            room_id:roomId,
            inviter_id:req.user.id,
            invitee_id:target.id,
            status:"pending"
          })
          .select("id")
          .single();

      if(error){

        if(
          error.code==="23505"
        ){

          return res
            .status(409)
            .json({
              error:
                "このユーザーには既に招待状を送っています。"
            });
        }

        throw error;
      }

      await emitInviteToUser(
        target.id,
        invite.id
      );

      res
        .status(201)
        .json({
          ok:true,
          inviteId:invite.id
        });

    }catch(error){

      console.error(
        "send group invite:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "招待状の送信に失敗しました。"
        });
    }
  }
);

app.post(
  "/api/invites/:inviteId/accept",
  requireAuth,
  async(req,res)=>{

    try{

      const inviteId=
        req.params.inviteId;

      const {
        data:invite,
        error:inviteError
      } =
        await supabase
          .from("room_invites")
          .select(`
            id,
            room_id,
            inviter_id,
            invitee_id,
            status,
            room:room_id (
              id,
              name,
              type,
              owner_id,
              created_at,
              updated_at
            )
          `)
          .eq(
            "id",
            inviteId
          )
          .eq(
            "invitee_id",
            req.user.id
          )
          .maybeSingle();

      if(inviteError){
        throw inviteError;
      }

      if(!invite){

        return res
          .status(404)
          .json({
            error:
              "招待状が見つかりません。"
          });
      }

      if(
        invite.status!=="pending"
      ){

        return res
          .status(409)
          .json({
            error:
              "この招待状は既に処理されています。"
          });
      }

      if(
        !invite.room ||
        invite.room.type!=="group"
      ){

        return res
          .status(400)
          .json({
            error:
              "このグループは存在しません。"
          });
      }

      const {
        error:memberError
      } =
        await supabase
          .from("room_members")
          .upsert(
            {
              room_id:
                invite.room_id,
              user_id:
                req.user.id,
              role:"member"
            },
            {
              onConflict:
                "room_id,user_id"
            }
          );

      if(memberError){
        throw memberError;
      }

      const {
        error:updateError
      } =
        await supabase
          .from("room_invites")
          .update({
            status:"accepted",
            responded_at:
              new Date()
                .toISOString()
          })
          .eq(
            "id",
            inviteId
          )
          .eq(
            "invitee_id",
            req.user.id
          );

      if(updateError){
        throw updateError;
      }

      await supabase
        .from("rooms")
        .update({
          updated_at:
            new Date()
              .toISOString()
        })
        .eq(
          "id",
          invite.room_id
        );

      io.to(
        `user:${req.user.id}`
      ).emit(
        "rooms:changed"
      );

      io.to(
        `room:${invite.room_id}`
      ).emit(
        "room:changed",
        {
          roomId:
            invite.room_id
        }
      );

      io.to(
        `user:${invite.inviter_id}`
      ).emit(
        "invite:changed",
        {
          roomId:
            invite.room_id
        }
      );

      res.json({
        ok:true,
        room:invite.room
      });

    }catch(error){

      console.error(
        "accept invite:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "招待の承認に失敗しました。"
        });
    }
  }
);

app.post(
  "/api/invites/:inviteId/reject",
  requireAuth,
  async(req,res)=>{

    try{

      const inviteId=
        req.params.inviteId;

      const {
        data:invite,
        error:findError
      } =
        await supabase
          .from("room_invites")
          .select(
            "id,room_id,inviter_id,status"
          )
          .eq(
            "id",
            inviteId
          )
          .eq(
            "invitee_id",
            req.user.id
          )
          .maybeSingle();

      if(findError){
        throw findError;
      }

      if(!invite){

        return res
          .status(404)
          .json({
            error:
              "招待状が見つかりません。"
          });
      }

      if(
        invite.status!=="pending"
      ){

        return res
          .status(409)
          .json({
            error:
              "この招待状は既に処理されています。"
          });
      }

      const {
        error
      } =
        await supabase
          .from("room_invites")
          .update({
            status:"rejected",
            responded_at:
              new Date()
                .toISOString()
          })
          .eq(
            "id",
            inviteId
          )
          .eq(
            "invitee_id",
            req.user.id
          );

      if(error){
        throw error;
      }

      io.to(
        `user:${invite.inviter_id}`
      ).emit(
        "invite:changed",
        {
          roomId:
            invite.room_id
        }
      );

      res.json({
        ok:true
      });

    }catch(error){

      console.error(
        "reject invite:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "招待の拒否に失敗しました。"
        });
    }
  }
);

/* =========================
   Socket.IO
========================= */

io.use(
  authenticateSocket
);

io.on(
  "connection",
  socket=>{

    const user=
      getSocketUser(
        socket
      );

    console.log(
      `socket connected: ${user.username}`
    );

    socket.join(
      `user:${user.id}`
    );

    socket.on(
      "room:join",
      async roomId=>{

        try{

          if(
            await isRoomMember(
              user.id,
              roomId
            )
          ){

            for(
              const room of socket.rooms
            ){

              if(
                room.startsWith(
                  "room:"
                )
              ){

                socket.leave(
                  room
                );
              }
            }

            socket.join(
              `room:${roomId}`
            );
          }

        }catch{}
      }
    );

    socket.on(
      "room:leave",
      roomId=>{

        socket.leave(
          `room:${roomId}`
        );
      }
    );

    socket.on(
      "disconnect",
      ()=>{

        console.log(
          `socket disconnected: ${user.username}`
        );
      }
    );
  }
);

/* =========================
   SPA fallback
========================= */

app.get(
  "/{*splat}",
  (req,res)=>{

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);

server.listen(
  PORT,
  ()=>{
    console.log(
      `schat server: http://localhost:${PORT}`
    );
  }
);
