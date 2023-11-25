const express = require("express");
const session = require("express-session");
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const secret = "carmensemeperdiolacadenita";
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const path = require("path");
const app = express();
const validator = require('validator');

// Configuraciones
app.set("view engine", "ejs"),
app.set("views", path.join(__dirname, "views"));
app.use("/assets", express.static("assets"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: secret,
    resave: false,
    saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

// Conexion a base de datos
const db = mysql.createConnection({
    host: "localhost",
    port: "3308",
    user: "root",
    password: "",
    database: "carminder"
});

db.connect((err) => {
    if (err) {
        console.log("Error al conectar a la base de datos: " + err.stack);
    } else {
        console.log("Conexión exitosa a la base de datos");
    }
});

// Configuración de Passport para trabajar con sesiones
passport.serializeUser((user, done) => {
    done(null, user.id_usuario); // Utilizar el ID del usuario en la sesión
});

passport.deserializeUser((id, done) => {
    // Obtener detalles del usuario desde la base de datos usando el ID
    const query = "SELECT * FROM usuarios WHERE id_usuario = ?";
    db.query(query, [id], (err, results) => {
        if (err) {
            console.error("Error al buscar el usuario: ", err);
            return done(err);
        }

        if (results.length === 0) {
            console.log("Usuario no encontrado");
            return done(null, false, { message: 'Usuario no encontrado' });
        }

        const usuario = results[0];
        return done(null, usuario);
    });
});

    // Configuración de Passport para la estrategia local de autenticación
passport.use(new LocalStrategy(
    { usernameField: 'correo_u', passwordField: 'contraseña_u' },
    (correo_u, contraseña_u, done) => {
        console.log(`Intento de inicio de sesión para el correo: ${correo_u}`);
        
    // Buscar el usuario en la base de datos por correo
const query = "SELECT * FROM usuarios WHERE correo_u = ?";
    db.query(query, [correo_u], (err, results) => {
    if (err) {
        console.error("Error al buscar el usuario: ", err);
        return done(err);
    }
    if (results.length === 0) {
        console.log("Usuario no encontrado");
        return done(null, false, { message: 'Usuario no encontrado' });
    }
const usuario = results[0];

    // Comparar contraseñas
bcrypt.compare(contraseña_u, usuario.contraseña_u, (err, result) => {
    if (err) {
        console.error("Error al comparar contraseñas: ", err);
        return done(err);
    }
    if (result) {
        console.log("Inicio de sesión exitoso");
        return done(null, usuario);
    } else {
        console.log("Contraseña incorrecta");
        return done(null, false, { message: 'Contraseña incorrecta' });
    }
});
    });
    }
));

// Rutas
app.get("/CarMinder", (req, res) => {
    res.render("CarMinder", {})
});

app.get("/register", (req, res) => {
    res.render("register", {})
});

app.get("/foro", (req, res) => {
    res.render("Foro", { user: req.user });
});

// Ruta Estado
app.get("/estado/:id_carro_usuario", ensureAuthenticated, (req, res) => {
    const userId = req.user.id_usuario;
    const idCarroUsuario = req.params.id_carro_usuario;

    // Obtener la información específica del coche del usuario desde la tabla carros_usuarios
    const queryCarrosUsuarios = "SELECT * FROM carros_usuarios WHERE id_usuario = ? AND id_carro_usuario = ?";

    db.query(queryCarrosUsuarios, [userId, idCarroUsuario], (err, resultsCarrosUsuarios) => {
        if (err) {
            console.error("Error al obtener información del coche del usuario desde carros_usuarios: ", err);
            res.status(500).send("Error al obtener información del coche del usuario");
            return;
        }

        const coche = resultsCarrosUsuarios[0]; // Tomamos el primer resultado, asumiendo que la consulta devuelve un solo resultado

        // Asegúrate de que 'coche' esté definido antes de continuar
        if (!coche) {
            res.status(404).send("Coche no encontrado en la tabla carros_usuarios");
            return;
        }

        // Obtener información adicional del coche desde la tabla carros usando el modelo
        const queryCarros = "SELECT * FROM carros WHERE modelo = ?";

        db.query(queryCarros, [coche.modelo], (err, resultsCarros) => {
            if (err) {
                console.error("Error al obtener información adicional del coche desde carros: ", err);
                res.status(500).send("Error al obtener información del coche del usuario");
                return;
            }

            const cocheBase = resultsCarros[0]; // Tomamos el primer resultado, asumiendo que la consulta devuelve un solo resultado

            // Asegúrate de que 'cocheBase' esté definido antes de renderizar la página
            if (cocheBase) {
                res.render("Estado", { user: req.user, coche: coche, cocheBase: cocheBase });
            } else {
                res.status(404).send("Coche no encontrado en la tabla carros");
            }
        });
    });
});


app.get("/configuracion", ensureAuthenticated, (req, res) => {
    res.render("configuracion", { user: req.user });
});

app.get("/agregarCoche", ensureAuthenticated, (req, res) => {
    res.render("agregarCoche", { user: req.user });
});

// En tu ruta de inicio, donde obtienes los coches para mostrar en la página principal
app.get("/inicio", ensureAuthenticated, (req, res) => {
    const userId = req.user.id_usuario;
    const query = "SELECT * FROM carros_usuarios WHERE id_usuario = ?";
    
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error("Error al obtener coches del usuario: ", err);
            res.status(500).send("Error al obtener coches del usuario");
        } else {
            // Renderiza la página de inicio y pasa los coches del usuario y la información del usuario
            res.render("inicio", { coches: results, user: req.user });
        }
    });
});


// Inicio de sesión
app.post('/login', passport.authenticate('local', {
    successRedirect: '/Inicio',
    failureRedirect: '/CarMinder?error=1'
}));

// Registro de usuario
app.post("/register", (req, res) => {
    const { nombre_u, correo_u, contraseña_u } = req.body;
    bcrypt.hash(contraseña_u, 10, (err, hash) => {
        if (err) {
            console.error("Error al encriptar la contraseña: ", err);
            res.status(500).send('<script>alert("Error al registrar"); window.location="/CarMinder";</script>');
        } else {
            const query = "INSERT INTO usuarios (nombre_u, correo_u, contraseña_u,created_at , active) VALUES (?, ?, ?,NOW() , 1)";
            db.query(query, [nombre_u, correo_u, hash], (err, results) => {
                if (err) {
                    console.error("Error al registrar el usuario: ", err);
                    res.status(500).send('<script>alert("Error al registrar"); window.location="/CarMinder";</script>');
                } else {
                    res.send('<script>alert("Usuario registrado con éxito"); window.location="/CarMinder";</script>');
                }
            });
        }
    });
});

// Ruta para cerrar sesión
app.get('/cerrar-sesion', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error("Error al cerrar sesión:", err);
            return next(err);
        }
        console.log("Sesión cerrada con éxito");
        res.redirect('CarMinder');
    });
});

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/CarMinder'); // Redirigir a la página de inicio de sesión si no está autenticado
}

//AgregarCoche
app.post('/agregarCoche', ensureAuthenticated, (req, res) => {
    const userId = req.user.id_usuario;
    const { marca, modelo, km_actual, uc_llantas, uc_aceite, uc_frenos, uc_liquido_frenos, uc_aceite_direccion, uc_filtro_aire, uc_bujias, uc_correas, uc_filtro_combustible, uc_suspension, uc_liquido_transmision } = req.body;
    console.log('Valores recibidos en la solicitud:', req.body);

    // Generar la ruta de la imagen
    const ruta_imagen = `/assets/imagenes/Vehiculos automotrices/${marca} ${modelo}.jpg`;

    // Insertar datos en la base de datos
    const query = "INSERT INTO carros_usuarios (id_usuario, marca, modelo, km_actual, uc_llantas, uc_aceite, uc_frenos, uc_liquido_frenos, uc_aceite_direccion, uc_filtro_aire, uc_bujias, uc_correas, uc_filtro_combustible, uc_suspension, uc_liquido_transmision, ruta_imagen, fecha_registro) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())";
    
    db.query(query, [userId, marca, modelo, km_actual, uc_llantas, uc_aceite, uc_frenos, uc_liquido_frenos, uc_aceite_direccion, uc_filtro_aire, uc_bujias, uc_correas, uc_filtro_combustible, uc_suspension, uc_liquido_transmision, ruta_imagen], (error, result) => {
        if (error) {
            console.error('Error al procesar el formulario de agregar coche:', error.message);
            console.error(error.stack);
            res.status(500).send('Error interno del servidor');
        } else {
            // Redireccionar a la página de inicio después de agregar el coche
            res.redirect('/inicio');
        }
    });
});


// Iniciar el servidor
app.listen(3000, () => {
    console.log("Corriendo en el puerto 3000");
});


