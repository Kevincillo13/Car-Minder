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
app.get("/login", (req, res) => {
    res.render("login", {})
});

app.get("/register", (req, res) => {
    res.render("register", {})
});

app.get("/foro", (req, res) => {
    res.render("Foro", { user: req.user });
});

app.get("/estado/:idCarro", ensureAuthenticated, (req, res) => {
    const cocheId = req.params.idCarro;

    obtenerInformacionDelCocheAlgunComo(cocheId, (err, coche) => {
        if (err) {
            // Manejar el error, por ejemplo, redirigir a una página de error
            res.status(404).send("Coche no encontrado");
        } else {
            res.render("Estado", { user: req.user, coche: coche });
        }
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


// Registro de usuario
app.post("/register", (req, res) => {
    const { nombre_u, apellido_u, correo_u, contraseña_u } = req.body;

    // Verificar si el correo ya está registrado
    db.query('SELECT id_usuario FROM usuarios WHERE correo_u = ?', [correo_u], (error, results) => {
        if (error) {
            console.error("Error:", error);
            return res.status(500).send('<script>alert("Error al registrar"); window.location="/register";</script>');
        }

        if (results.length > 0) {
            // El correo ya está en uso
            return res.status(400).send('<script>alert("El correo electrónico ya está registrado"); window.location="/register";</script>');
        }

        // Hash de la contraseña
        bcrypt.hash(contraseña_u, 10, (hashError, hash) => {
            if (hashError) {
                console.error("Error al generar el hash:", hashError);
                return res.status(500).send('<script>alert("Error al registrar"); window.location="/register";</script>');
            }

            // Si el correo no está registrado, proceder con la inserción
            db.query('INSERT INTO usuarios (nombre_u, correo_u, contraseña_u, created_at, active) VALUES (?, ?, ?, NOW(), 1)',
                [nombre_u + " " + apellido_u, correo_u, hash],
                (insertError, results) => {
                    if (insertError) {
                        console.error("Error al insertar en la base de datos:", insertError);
                        return res.status(500).send('<script>alert("Error al registrar"); window.location="/register";</script>');
                    }

                    // Registro exitoso
                    res.send('<script>alert("Usuario registrado con éxito"); window.location="/login";</script>');
                }
            );
        });
    });
});


// Inicio de sesión
app.post('/login', passport.authenticate('local', {
    successRedirect: '/inicio',
    failureRedirect: '/login?error=1'
}));

// Ruta para cerrar sesión
app.get('/cerrar-sesion', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error("Error al cerrar sesión:", err);
            return next(err);
        }
        console.log("Sesión cerrada con éxito");
        res.redirect('/login');
    });
});

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login'); // Redirigir a la página de inicio de sesión si no está autenticado
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

// Ruta para manejar la actualización de nombre
app.post("/actualizar-nombre", ensureAuthenticated, (req, res) => {
    const userId = req.user.id_usuario;
    const { nombre_u } = req.body;

    // Realiza la consulta de actualización en la base de datos
    const query = "UPDATE usuarios SET nombre_u = ? WHERE id_usuario = ?";

    db.query(query, [nombre_u, userId], (error, results) => {
        if (error) {
            console.error("Error al actualizar nombre:", error);
            res.status(500).send('<script>alert("Error al actualizar nombre"); window.location="/configuracion";</script>');
        } else {
            // Actualización exitosa
            res.send('<script>alert("Actualización exitosa"); window.location="/configuracion";</script>');
        }
    });
});

// Ruta para manejar la actualización de correo
app.post("/actualizar-correo", ensureAuthenticated, (req, res) => {
    const userId = req.user.id_usuario;
    const { correo_u } = req.body;

    // Realiza la consulta de actualización en la base de datos
    const query = "UPDATE usuarios SET correo_u = ? WHERE id_usuario = ?";

    db.query(query, [correo_u, userId], (error, results) => {
        if (error) {
            console.error("Error al actualizar correo:", error);
            res.status(500).send('<script>alert("Error al actualizar correo"); window.location="/configuracion";</script>');
        } else {
            // Actualización exitosa
            res.send('<script>alert("Actualización exitosa"); window.location="/configuracion";</script>');
        }
    });
});

// Ruta para eliminar coches y cuenta del usuario
app.post('/eliminar-cuenta', ensureAuthenticated, (req, res) => {
    const userId = req.user.id_usuario;

    // Eliminar coches del usuario
    const deleteCarsQuery = "DELETE FROM carros_usuarios WHERE id_usuario = ?";
    db.query(deleteCarsQuery, [userId], (errorCars, resultCars) => {
        if (errorCars) {
            console.error('Error al eliminar coches del usuario:', errorCars.message);
            console.error(errorCars.stack);
            res.status(500).send('Error interno del servidor');
        } else {
            console.log('Coches eliminados con éxito');
            
            // Eliminar cuenta del usuario después de eliminar coches
            const deleteAccountQuery = "DELETE FROM usuarios WHERE id_usuario = ?";
            db.query(deleteAccountQuery, [userId], (errorAccount, resultAccount) => {
                if (errorAccount) {
                    console.error('Error al eliminar cuenta del usuario:', errorAccount.message);
                    console.error(errorAccount.stack);
                    res.status(500).send('Error interno del servidor');
                } else {
                    console.log('Cuenta de usuario eliminada con éxito');
                    // Redirigir al usuario a una página de confirmación o a otra ubicación según tu flujo
                    res.send('<script>alert("Cuenta eliminada con éxito"); window.location.href = "/login";</script>');
                }
            });
        }
    });
});

// Esta función debería obtener la información del coche según su ID
function obtenerInformacionDelCocheAlgunComo(cocheId, callback) {
    const query = "SELECT * FROM carros_usuarios WHERE id_carro_usuario = ?";
    db.query(query, [cocheId], (err, results) => {
        if (err) {
            console.error("Error al obtener la información del coche:", err);
            callback(err, null);
        } else {
            if (results.length > 0) {
                const informacionDelCoche = results[0];
                callback(null, informacionDelCoche);
            } else {
                // No se encontró ningún coche con el ID proporcionado
                callback("Coche no encontrado", null);
            }
        }
    });
}

// Iniciar el servidor
app.listen(3000, () => {
    console.log("Corriendo en el puerto 3000");
});


