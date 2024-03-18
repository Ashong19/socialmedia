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
app.post("/register",upload.single("avatar"),(req,res) => {
    const userQuery = "INSERT INTO users(`firstname`,`lastname`,`email`,`password`,`avatar`) VALUES(?)";
    bcrypt.hash(req.body.password.toString(), salt, (err, hashPass) => {
        console.log(hashPass);
        if(err) return res.json([{Error : "Error Hash Password"}]);

        const values = [
            req.body.firstname, 
            req.body.lastname, 
            req.body.email, 
            hashPass, 
            req.file.filename];
        
        db.query(userQuery,[values],(err, result) => {
            if(err) return res.json({Error: "Not Inserted"})
            return res.json({Status: "User account successfully created"});
        })
    })
});

// get Users 
app.get("/users",(req,res) => {
    const userQuery = "SELECT * FROM users";
    db.query(userQuery, (err,result) => {
        if(err){
            console.log(err);
            res.json(err);
        }else{
            res.json(result);
        }
    });
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

const verifyUsers = (req, res, next) => {
    const token = req.cookies.jwtCookie;
    console.log({"Token": token})
    if(!token){
        return res.json({Message: "404 | Unauthorized Page"});
    }else{
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if(err){
                return res.json({Message: "Token Error"});
            }else{
                req.email = decoded.email;
                next();
            }
        } )
    }
}

app.get('/profile', verifyUsers, (req, res)=>{
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
    res.send(req.email)
    return res.json({Status: "Success", email: req.email});
});



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
    const { email, password } = req.body;
    //Check if username and password are present
    if (!email || !password) {
        return res.status(400).json({ message: 'Username and Password are Required' });
    }

    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], async (err, result) => {
        if (err || result.length === 0) {
            console.log("Error Searching for Email: " + err)
            res.status(404).json({ message: "No Email Exist" })
        } else {
            //compare hashed password
            const match = await bcrypt.compare(password, result[0].password);
            if (match) {
                const id = result[0].email;
                const token = jwt.sign({id}, process.env.JWT_SECRET, {expiresIn: process.env.JWT_EXPIRES});
                const cookieOption = {expires: Date.now()+process.env.JWT_COOKIE_EXPIRE, httpOnly: true}; //to prevent hacking

                res.cookie('jwtCookie',token);
                res.json({ message: 'Login Successful', token })
                
            } else {
                res.status(401).json({ message: 'Invalid Password' })
            }
        }
    })
});