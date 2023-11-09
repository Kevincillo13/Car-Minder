    //Declarar variables constantes
const express= require("express");
const session = require("express-session");
const secret = "carmensemeperdiolacadenita";
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const path = require("path");
const app= express(); 
const validator = require('validator');

    //Configuraciones
app.set("view engine", "ejs"),
app.set("views", path.join(__dirname, "views"));
app.use("/assets",express.static("assets"));
app.use(bodyParser.urlencoded({ extended: true}));
app.use(session({
    secret: secret,
    resave: false,
    saveUninitialized: true
}));

app.listen (3000, (req,res)=> {
    console.log("Corriendo en el puerto 3000")
})

    //Conexion a base de datos
const db = mysql.createConnection({
    host: "localhost",
    port: "3308",
    user: "root",
    password: "",
    database: "carminder"
});

db.connect((err)=>{
    if (err){
        console.log("Error al conectar a la base de datos: " + err.stack);
    } 
    else{
        console.log("Conexión exitosa a la base de datos");
    }
})

    // Paginas 
app.get("/login",(req,res)=>{
    res.render("login",{})
})
app.get("/register",(req,res)=>{
    res.render("register",{})
})
app.get("/foro",(req,res)=>{
    res.render("Foro",{})
})
app.get("/estado",(req,res)=>{
    res.render("Estado",{})
})
app.get("/configuracion",(req,res)=>{
    res.render("configuracion",{})
})
app.get("/agregarCoche",(req,res)=>{
    res.render("agregarCoche",{})
})
app.get("/inicio",(req,res)=>{
    res.render("inicio",{})
})

// Registro de usuario
app.post("/register", (req, res) => {
    const { correo_u, contraseña_u } = req.body;
    bcrypt.hash(contraseña_u, 10, (err, hash) => {
        if (err) {
            console.error("Error al encriptar la contraseña: ", err);
            res.status(500).send('<script>alert("Error al registrar"); window.location="/register";</script>');
        } else {
            const query = "INSERT INTO usuarios (correo_u, contraseña_u) VALUES (?, ?)";
            db.query(query, [correo_u, hash], (err, results) => {
                if (err) {
                    console.error("Error al registrar el usuario: ", err);
                    res.status(500).send('<script>alert("Error al registrar"); window.location="/register";</script>');
                } else {
                    res.redirect("/login");
                }
            });
        }
    });
});

// Inicio de sesión
app.post("/login", (req, res) => {
    const { correo_u, contraseña_u } = req.body;
    const query = "SELECT * FROM usuarios WHERE correo_u = ?";
    db.query(query, [correo_u], (err, results) => {
        if (err) {
            console.error("Error al buscar el usuario: ", err);
            res.status(500).send('<script>alert("Error al iniciar sesión"); window.location="/login";</script>');
        } else if (results.length > 0) {
            const usuario = results[0];
            bcrypt.compare(contraseña_u, usuario.contraseña_u, (err, result) => {
                if (result) {
                    req.session.userId = usuario.id_usuario;
                    res.redirect("/inicio");
                } else {
                    res.status(400).send('<script>alert("Contraseña incorrecta"); window.location="/login";</script>');
                }
            });
        } else {
            res.status(400).send('<script>alert("Usuario no encontrado"); window.location="/login";</script>');
        }
    });
});
