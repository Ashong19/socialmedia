import express from "express";
// for database connection
import mysql from "mysql2";
import dotenv from "dotenv";
dotenv.config({path: "./.env"});
import cors from "cors";
import bcrypt from 'bcrypt';
import multer from "multer";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
const salt = 10;



const db = mysql.createConnection({
    user: process.env.DATABASE_USER,
    host: process.env.DATABASE_HOST,
    database: process.env.DATABASE,
    password: process.env.DATABASE_PASSWORD,
    port: process.env.DATABASE_PORT,
});

db.connect((error) => {
    if(error){
        console.log("Database not connected", error);
    }else{
        console.log("Database Connected");
    }
});

const storage = multer.diskStorage({
    destination: (req,file,cb) => {cb(null,"public/images")},
    filename: (req,file,cb) => { cb(null,file.originalname)}
    });


const upload = multer({storage: storage});

const app = express();
const appPort = 3001;

app.listen(appPort, () => {
    console.log("Server is Running");
});

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Credentials", true);
    next();
  });

app.use(express.json());
// middleware of nodejs
app.use(cors(
    {
    origin: "http://localhost:3000",
    methods: ["POST","GET","PUT","DELETE"],
    credentials: true
}
));
app.use(cookieParser());
app.use(express.static('public'));

// Adding User Account
app.post("/register",upload.single("image"),(req,res) => {
    const userQuery = "INSERT INTO users(`firstname`,`lastname`,`email`,`password`,`city`,`image`) VALUES(?)";
    bcrypt.hash(req.body.password.toString(), salt, (err, hashPass) => {
        console.log(hashPass);
        if(err) return res.json([{Error : "Error Hash Password"}]);

        const values = [
            req.body.firstname, 
            req.body.lastname, 
            req.body.email, 
            hashPass, 
            req.body.city, 
            req.file.filename];
        
            db.query(userQuery,[values],(err, result) => {
            if(err) return res.json({Error: "Not Inserted"})
            return res.json({Status: "User account successfully created"});
        })
    })
});
// Update Profile

app.put("/update/:userId",upload.single("image"),(req,res) => {
    const {userId} = req.params;
    const updateQuery = "UPDATE users SET firstname = ?, lastname = ?, city = ?, description = ?, image = ? WHERE user_id = ?";
    db.query(updateQuery, [req.body.firstname, req.body.lastname, req.body.city, req.body.description,req.file.filename,userId  ], (err,result) => {
        if(err){
            console.log(err);
             res.json(err);
        }else{
             res.json(result[0]);
        }
    });
});



// get Users 
app.get("/users/:userId",(req,res) => {

    const token = req.cookies.jwtCookie;
    if(!token) return res.status(401).json("Not Logged In");

    jwt.verify(token, process.env.JWT_SECRET, (err, userInfo)=> {
        if(err) return res.status(403).json("Token not Valid");

        const {userId} = req.params;
        const userQuery = "SELECT * FROM users WHERE user_id = ?";
        console.log(userId)
        db.query(userQuery,[userId],(err,result) => {
        if(err) return res.status(500).json(err)
        // const {password, ...info} = result[0]
            return res.json(result[0]);
    });
    
    })



    
});

// const verifyUsers = (req, res, next) => {
//     // const token = req.cookies.token;
//     const token = req.header('Authorization');
//     console.log("Unextracted Token: " + token)

//     if (!token) {
//         return res.status(401).json({ message: "Unauthorized" })
//     }
//         const extractedToken = token.split(' ')[1];
//         console.log('Actual TOken: ' + extractedToken)
//         try {
//             // /verift and validate our token
//             const decoded = jwt.verify(extractedToken, process.env.JWT_SECRET)
//             req.userId = decoded.userId;
//             console.log({"user id": req.user_id})
//             next();

//         } catch (err) {
//             res.status(401).json({ message: "Invalid Token" })
//         }
// }

// const verifyUsers = (req, res, next) => {
//     const token = req.cookies.jwtCookie;
//     console.log({"Token": token})
//     if(!token){
//         return res.json({Error: "404 | Unauthorized Page"});
//     }else{
//         jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
//             if(err){
//                 return res.json({Error: "Token Error"});
//             }else{
//                 req.id = decoded.id;
//                 next();
//             }
//         } )
//     }
// }

// app.get('/profile', verifyUsers, (req, res)=>{
    // const user_id = req.user_id;
    // const sql = "SELECT * FROM users WHERE user_id = ?";
    // db.query(sql, [user_id], (err, result)=>{
    //     if(err){
    //         console.log(err)
    //     }
    //     if (result.length === 0) {   
    //         res.status(500).json({message: "Error Fetching Details"})
    //     }else{
    //         res.json({firstname: result[0].firstname});
    //     }
    // })
//     return res.json({Status: "Success", id: req.id});
// });



// app.post("/login", (req,res) => {

//         const { email, password } = req.body;
//         //Check if username and password are present
//         if (!email || !password) {
//             return res.status(400).json({ message: 'Username and Password are Required' });
//         }
//         const userQuery = "SELECT * FROM users WHERE email = ?";
//         db.query(userQuery,[req.body.email], (err, data) => {
//             if(err)return res.json({message: "Server Login error"});
//             if(data.length > 0){
//                 bcrypt.compare(req.body.password.toString(), data[0].password,
//                     (err, response) => {
//                         if(err) return res.json({message: "Password Compare error"});
//                         if(response){
//                                 const token = jwt.sign({ user_id: data[0].user_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
//                                 res.json({ message: 'Login Successful', token })
//                             }else{
//                             return res.json({message: "Password not Match"});
//                         }
//                     })
                
//             }else{
//                 return res.json({Error: "No Email Existed"});
//             }
//         })
// });

app.post('/login', async (req, res) => {
    const {email, password } = req.body;
    //Check if username and password are present
    if (!email || !password) {
        return res.status(400).json({ message: 'Username and Password are Required' });
    }

    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [req.body.email], async (err, result) => {
        if (err || result.length === 0) {
            console.log("Error Searching for Email: " + err)
            return res.status(404).json({ message: "No Email Exist" })
        } else {
            //compare hashed password
            const match = await bcrypt.compare(password, result[0].password);
            if (match) {
                const id = result[0].user_id;
                const token = jwt.sign({id}, process.env.JWT_SECRET, {expiresIn: process.env.JWT_EXPIRES});
                const {password, ...other} = result[0]

                // res.cookie('jwtCookie',token,{httpOnly: true,});
                // res.json({ message: 'Login Successful', token })
                return res.cookie("jwtCookie", token, {httpOnly: true,}).status(200).json(other);
                
            } else {
                return res.status(401).json({ message: 'Invalid Password' })
            }
        }
    })
});

// app.post("/login", (req,res) => {
//     const q = "SELECT * FROM users WHERE email = ?";

//     db.query(q, [req.body.email], (err, data) => {
//       if (err) return res.status(500).json(err);
//       if (data.length === 0) return res.status(404).json("User not found!");
  
//       //Check password
//       const isPasswordCorrect = bcrypt.compare(
//         req.body.password,
//         data[0].password
//       );
  
//       if (!isPasswordCorrect)
//         return res.status(400).json("Wrong username or password!");
  
//       const token = jwt.sign({ id: data[0].user_id }, "jwtkey");
//       const { password, ...other } = data[0];
//       console.log(other)
//       res
//         .cookie("access_token", token, {
//           httpOnly: true,
//         })
//         .status(200)
//         .json(other);
//     });
// })

app.post("/logout", async (req, res) => {
    try {
     res.clearCookie("jwtCookie");
     return res.json({ message: "Signout success" });
    } catch (err) {
     console.log(err);
     return res.status(400).send("Error. Try again.");
    }
   });


//    get Post

app.get("/posts", (req, res) =>{

    const postQuery = "SELECT p.post_id AS postId,u.user_id AS userId, u.firstname AS firstname, u.lastname AS lastname, u.image as userImg, u.city as city, p.description as postDesc, p.post_image as postImg, p.date_created as date FROM users u JOIN post p ON u.user_id = p.uid ORDER BY p.date_created DESC"
    db.query(postQuery, (err,result) => {
        if(err) return res.json(err)

        return res.status(200).json(result)
    })
});

// deletePost

app.delete("/delete/:postId",(req,res)=>{

    const token = req.cookies.jwtCookie;
    if(!token) return res.status(401).json("Not Logged In");

    jwt.verify(token, process.env.JWT_SECRET, (err, userInfo)=> {
        if(err) return res.status(403).json("Token not Valid");

        const delQuery = "DELETE FROM post WHERE `post_id` = ? AND `user_id` = ?`";

        db.query(delQuery,[req.params.postId, userInfo.id],(err, result) => {
            console.log(result)
            if(err) return res.status().json(err);
            if(result.affectedRows>0) return res.status().json("Post has been deleted");
            return res.status(403).json("You can delete only your post");
        })
    })

});

// add Post

app.post("/addpost",upload.single("image"), (req,res)=>{

    const token = req.cookies.jwtCookie;
    if(!token) return res.status(401).json("Not Logged In");

    jwt.verify(token, process.env.JWT_SECRET, (err, userInfo)=> {
        if(err) return res.status(403).json("Token not Valid");

        const addPostQuery = "INSERT INTO post(`description`,`post_image`,`uid`) VALUES (?)";

        const values = [
            req.body.description,
            req.file.filename,
            userInfo.id];

        db.query(addPostQuery,[values],(err, result) => {
            console.log(result)
            if(err) return res.json({Error: "Not Inserted"})
            return res.json({Status: "User account successfully created"});
        })
    })

});

// get Comments on a post

app.get("/comments", (req, res) =>{
    const comQuery = `SELECT c.*, u.user_id AS userId, u.firstname as firstname,u.lastname as lastname, u.image profile FROM comments AS c JOIN users AS u ON (u.user_id = c.user_id)
    WHERE c.post_id = ? ORDER BY c.date_entered DESC`;    
    
    db.query(comQuery,[req.query.postId], (err,result) => {
        console.log(result)
        if(err){
            console.log(err)
        }
        return res.status(200).json(result)
    })
});

// for adding comment
app.post("/addcomment", (req,res)=>{

    const token = req.cookies.jwtCookie;
    if(!token) return res.status(401).json("Not Logged In");

    jwt.verify(token, process.env.JWT_SECRET, (err, userInfo)=> {
        if(err) return res.status(403).json("Token not Valid");

        const addCommentQuery = "INSERT INTO comments(`description`,`user_id`,`post_id`) VALUES (?)";

        const values = [
            req.body.newComment,
            userInfo.id,
            req.body.postId];

        db.query(addCommentQuery,[values],(err, result) => {
            console.log(result)
            if(err) return res.json({Error: "Not Inserted"})
            return res.json({Status: "Comment successfully created"});
        })
    })

});

// Likes

// app.get("/likes", (req, res) => {
    
//     const likesQuery = "SELECT user_id FROM likes WHERE post_id = ?"

//     db.query(likesQuery,[req.query.postId],(err,result) => {
//         if(err) return res.status(500).json(err);
//         return res.json(200).json(result.map(like=>like.user_id))
//     })
// })

app.post("/addlike", (req,res) => {
    const token = req.cookies.jwtCookie;
    if(!token) return res.status(401).json("Not Logged In");

    jwt.verify(token, process.env.JWT_SECRET, (err, userInfo)=> {
        if(err) return res.status(403).json("Token not Valid");

        const addLikeQuery = "INSERT INTO likes(`user_id`,`post_id`) VALUES (?)";

        const values = [
            userInfo.id,
            req.body.postId];

        db.query(addLikeQuery,[values],(err, result) => {
            console.log(result)
            if(err) return res.json(err)
            return res.json({Status: "Post Liked"});
        })
    })
})

app.post("/deletelike", (req,res) => {
    const token = req.cookies.jwtCookie;
    if(!token) return res.status(401).json("Not Logged In");

    jwt.verify(token, process.env.JWT_SECRET, (err, userInfo)=> {
        if(err) return res.status(403).json("Token not Valid");

        const delLikeQuery = "DELETE FROM likes WHERE `user_id` = ? AND `post_id` = ?";

        const values = [
            userInfo.id,
            req.query.postId];

        db.query(delLikeQuery,[values],(err, result) => {
            console.log(result)
            if(err) return res.json(err)
            return res.json({Status: "Like Removed"});
        })
    })
})