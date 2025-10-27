require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const postmark = require('postmark');
const crypto = require("crypto");


const app = express();
app.use(express.json({ limit: '50mb' })); // Augmente la limite pour les données JSON
app.use(express.urlencoded({ limit: '50mb', extended: true })); // Augmente la limite pour les données URL-encoded
app.use(cors());


const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  //ssl: {
    //  rejectUnauthorized: true,  // Assurez-vous que l'authentification SSL est activée
  //}
};

let db;

function handleDisconnect() {
  db = mysql.createConnection(dbConfig);

  db.connect((err) => {
    if (err) {
      console.error("Erreur de connexion à MySQL : ", err);
      setTimeout(handleDisconnect, 2000); // Réessaye après 2 secondes
    } else {
      console.log("Connecté à MySQL !");
    }
  });

  db.on("error", (err) => {
    console.error("Erreur MySQL :", err);
    if (err.code === "PROTOCOL_CONNECTION_LOST" || err.code === "ECONNRESET") {
      console.log("Reconnexion en cours...");
      handleDisconnect();
    } else {
      throw err;
    }
  });
}

handleDisconnect();

// Configuration de NodeMailer
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false, // true pour 465, false pour d'autres ports
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  connectionTimeout: 5000, // délai d'attente en ms
});

// Fonction pour envoyer un email avec NodeMailer
const sendEmail = (to, subject, text, attachments = []) => {
  const mailOptions = {
    from: '"SUPPORT LOCA CAR" <aissiaissa095@gmail.com>', // Expéditeur
    to, // Destinataire
    subject, // Sujet de l'email
    text, // Contenu de l'email en texte brut
    html,
    attachments: attachments
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error sending email: ', error);
    } else {
      console.log('Email sent: ' + info.response);
    }
  });
};

const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];

  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Récupérer toutes les voitures disponibles
app.get("/api/cars", (req, res) => {
  const sql = `
    SELECT
      cars.id,
      cars.marque AS brand,
      cars.modele AS model,
      cars.annee AS year,
      cars.type_carburant AS fuel,
      cars.boite_vitesse AS transmission,
      cars.prix_par_jour AS price,
      cars.duree_mini_en_jour,
      cars.photo AS image,
      cars.created_at,
      agences.ville AS city,
      cars.ville_car,
      cars.premium,
      agences.nom AS agence_nom,
      agences.avatar AS agence_avatar,
      agences.telephone AS agence_tel
    FROM cars
    INNER JOIN agences ON cars.agence_id = agences.id
    WHERE cars.disponible = 1
  `;

  db.query(sql, (err, rows) => {
    if (err) {
      console.error("Erreur récupération voitures:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    res.json(rows);
  });
});


app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  const sql = `
    SELECT u.id, u.username, u.password, u.typeUser, u.agence_id, u.is_verified, a.nom AS nomAgence
    FROM users u
    LEFT JOIN agences a ON u.agence_id = a.id
    WHERE u.username = ?
  `;

  db.query(sql, [username], async (err, rows) => {
    if (err) return res.status(500).json("Erreur serveur");
    if (rows.length === 0) return res.status(401).json("Identifiants invalides");

    const user = rows[0];

    // 🔹 Vérifier si l'email est validé
    if (!user.is_verified) {
      return res.status(403).json("Veuillez vérifier votre email avant de vous connecter.");
    }

    // 🔹 Vérification du mot de passe avec bcrypt
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json("Identifiants invalides");
    }

    const token = jwt.sign(
      { id: user.id, typeUser: user.typeUser, agence_id: user.agence_id },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      token,
      id: user.id,
      username: user.username,
      typeUser: user.typeUser,
      agence_id: user.agence_id,
      nomAgence: user.nomAgence || user.username,
    });
  });
});



//----------------------------------------------------------------------- Register
//app.use('/register', authenticateJWT);

app.post('/api/register', (req, res) => {
  const { nom, email, telephone, ville, username, password, typeUser } = req.body;

  // Vérifier si l'email existe déjà dans agences
  const checkAgenceQuery = 'SELECT * FROM agences WHERE email = ?';
  db.query(checkAgenceQuery, [email], (err, results) => {
    if (err) return res.status(500).send('Erreur du serveur (check agence)');
    if (results.length > 0) return res.status(400).send('Email déjà utilisé');

    // Vérifier si le username existe déjà dans users
    const checkUserQuery = 'SELECT * FROM users WHERE username = ?';
    db.query(checkUserQuery, [username], (err, results) => {
      if (err) return res.status(500).send('Erreur du serveur (check user)');
      if (results.length > 0) return res.status(400).send('Nom d\'utilisateur déjà pris');

      // Hacher le mot de passe
      const saltRounds = 10;
      bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) return res.status(500).send('Erreur lors du hachage du mot de passe');

        // 1. Insérer l'agence
        const insertAgence = 'INSERT INTO agences (nom, email, telephone, password, ville) VALUES (?, ?, ?, ?, ?)';
        db.query(insertAgence, [nom, email, telephone, hash, ville], (err, result) => {
          if (err) {
            console.error(err);
            return res.status(500).send('Erreur insertion agence');
          }

          const agenceId = result.insertId;

          // 🔹 Générer token de vérification
          const verificationToken = crypto.randomBytes(32).toString("hex");

          // 2. Insérer l'utilisateur lié à cette agence
          const insertUser = 'INSERT INTO users (username, password, typeUser, agence_id, is_verified, verification_token) VALUES (?, ?, ?, ?, 0, ?)';
          db.query(insertUser, [username, hash, typeUser, agenceId, verificationToken], (err, result2) => {
            if (err) {
              console.error(err);
              return res.status(500).send('Erreur insertion utilisateur');
            }
            // 🔹 Lien de vérification
            const verifyUrl = `${process.env.FRONTEND_URL}/verify-email/${verificationToken}`;

            sendEmail(
              email,
              "Vérifiez votre compte",
              `Bienvenue ${nom},\n\nMerci pour votre inscription. Cliquez sur le lien suivant pour activer votre compte :\n${verifyUrl}\n\n`
            );

            res.status(201).send('Inscription réussie. Vérifiez votre email pour activer votre compte.');
          });
        });
      });
    });
  });
});

//----------------------------------------------------------------------- Register

// ==================== VERIFY EMAIL ====================
app.get("/api/verify-email/:token", (req, res) => {
  const { token } = req.params;

  const sql = "SELECT id FROM users WHERE verification_token = ?";
  db.query(sql, [token], (err, results) => {
    if (err) return res.status(500).send("Erreur serveur");
    if (results.length === 0) return res.status(400).send("Lien invalide ou expiré");

    const userId = results[0].id;

    const updateSql = "UPDATE users SET is_verified=1, verification_token=NULL WHERE id=?";
    db.query(updateSql, [userId], (err2) => {
      if (err2) return res.status(500).send("Erreur serveur");
      res.send("Votre email a été vérifié avec succès. Vous pouvez maintenant vous connecter.");
    });
  });
});

//------------------------------------------------------------------------ Change password
app.put('/change-password', (req, res) => {
  const { username, currentPassword, newPassword } = req.body;

  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) {
      console.error('Erreur SQL:', err);
      return res.status(500).json({ message: 'Erreur du serveur' });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: 'Utilisateur non trouvé' });
    }

    const user = results[0];

    bcrypt.compare(currentPassword, user.password, (err, isMatch) => {
      if (err) {
        console.error('Erreur bcrypt:', err);
        return res.status(500).json({ message: 'Erreur du serveur' });
      }

      if (!isMatch) {
        return res.status(400).json({ message: 'Mot de passe actuel incorrect' });
      }

      bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
        if (err) {
          console.error('Erreur de hachage:', err);
          return res.status(500).json({ message: 'Erreur du serveur' });
        }

        db.query('UPDATE users SET password = ? WHERE username = ?', [hashedPassword, username], (err, result) => {
          if (err) {
            console.error('Erreur SQL lors de la mise à jour:', err);
            return res.status(500).json({ message: 'Erreur lors de la mise à jour du mot de passe' });
          }

          res.status(200).json({ message: 'Mot de passe changé avec succès' });
        });
      });
    });
  });
});

//------------------------------------------------------------------------------change password


//------------------------------------------------------------------------------get Users

app.get('/users', (req, res) => {
  const query = 'SELECT username FROM users';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Erreur lors de la récupération des utilisateurs:', err);
      return res.status(500).send('Erreur lors de la récupération des utilisateurs');
    }
    res.json(results);
  });
});


//------------------------------------------------------------------------------get Users





//------------------------------------------------------------------------------Delete User

app.delete("/api/users/:username", (req, res) => {
  const { username } = req.params;

  // 1. Vérifier si l'utilisateur existe
  const getUserQuery = 'SELECT * FROM users WHERE username = ?';
  db.query(getUserQuery, [username], (err, results) => {
    if (err) {
      console.error('Erreur lors de la récupération de l\'utilisateur:', err);
      return res.status(500).send('Erreur lors de la récupération de l\'utilisateur');
    }

    if (results.length === 0) {
      return res.status(404).send('Utilisateur non trouvé');
    }

    const user = results[0];

    // 2. Si ce n'est pas une agence, supprimer juste l'utilisateur
    if (user.typeUser !== 'agence' || !user.agence_id) {
      const deleteUserQuery = 'DELETE FROM users WHERE username = ?';
      return db.query(deleteUserQuery, [username], (err, result) => {
        if (err) {
          console.error('Erreur lors de la suppression de l\'utilisateur:', err);
          return res.status(500).send('Erreur lors de la suppression de l\'utilisateur');
        }

        return res.status(200).send('Utilisateur supprimé avec succès');
      });
    }

    // 3. Si c'est une agence → suppression en chaîne
    const agenceId = user.agence_id;

    const deletePhotosQuery = 'DELETE FROM photossupplemetairs WHERE agence_id = ?';
    db.query(deletePhotosQuery, [agenceId], (err) => {
      if (err) {
        console.error('Erreur lors de la suppression des photos supplémentaires:', err);
        return res.status(500).send('Erreur lors de la suppression des photos supplémentaires');
      }

      const deleteCarsQuery = 'DELETE FROM cars WHERE agence_id = ?';
      db.query(deleteCarsQuery, [agenceId], (err) => {
        if (err) {
          console.error('Erreur lors de la suppression des voitures:', err);
          return res.status(500).send('Erreur lors de la suppression des voitures');
        }

        const deleteAgenceQuery = 'DELETE FROM agences WHERE id = ?';
        db.query(deleteAgenceQuery, [agenceId], (err) => {
          if (err) {
            console.error('Erreur lors de la suppression de l\'agence:', err);
            return res.status(500).send('Erreur lors de la suppression de l\'agence');
          }

          const deleteUserQuery = 'DELETE FROM users WHERE username = ?';
          db.query(deleteUserQuery, [username], (err) => {
            if (err) {
              console.error('Erreur lors de la suppression de l\'utilisateur:', err);
              return res.status(500).send('Erreur lors de la suppression de l\'utilisateur');
            }

            return res.status(200).send('Utilisateur, agence, voitures et photos supprimés avec succès');
          });
        });
      });
    });
  });
});


//------------------------------------------------------------------------------Delete User



// ==================== AJOUTER UNE VOITURE ====================

// ----------------------------
// Middleware auth
// ----------------------------

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token manquant" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Token invalide" });
    req.user = decoded; // contient agence_id, typeUser, etc.
    next();
  });
}

// ----------------------------
// Récupérer les voitures de l'agence connectée
// ----------------------------
app.get("/api/cars/mine", authenticateToken, (req, res) => {
  const agence_id = req.user.agence_id; // ✅ récupéré du token
  const sql = "SELECT * FROM cars WHERE agence_id = ?";
  db.query(sql, [agence_id], (err, rows) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    res.json(rows);
  });
});


// ----------------------------
// ----------------------------
// Récupérer une voiture + ses photos supplémentaires
// ----------------------------
app.get("/api/cars/:id", authenticateToken, (req, res) => {
  const carId = req.params.id;

  const sqlCar = "SELECT * FROM cars WHERE id = ?";
  db.query(sqlCar, [carId], (err, rows) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    if (rows.length === 0) return res.status(404).json({ error: "Voiture introuvable" });

    const car = rows[0];
    const sqlPhotos = "SELECT id, agence_id, car_id, photoSuppl, created_at FROM photossupplemetairs WHERE car_id = ?";
    db.query(sqlPhotos, [carId], (err2, photos) => {
      if (err2) return res.status(500).json({ error: "Erreur chargement photos" });
      car.photos = photos; // chaque photo contient agence_id + car_id
      res.json(car);
    });
  });
});


// ----------------------------
// Ajouter une voiture
// ----------------------------
app.post("/api/cars", authenticateToken, (req, res) => {
  if (req.user.typeUser !== "agence")
    return res.status(403).json({ error: "Réservé aux agences" });

  const { marque, modele, annee, prix_par_jour, photo, type_carburant, boite_vitesse, ville_car, duree_mini_en_jour } = req.body;

  // Limite 25 voitures
  const checkSql = "SELECT COUNT(*) AS total FROM cars WHERE agence_id = ?";
  db.query(checkSql, [req.user.agence_id], (err, rows) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    if (rows[0].total >= 25) {
      return res.status(400).json({ error: "Vous ne pouvez pas ajouter plus de 25 voitures" });
    }

    const insertSql = `
      INSERT INTO cars (agence_id, marque, modele, annee, prix_par_jour, photo, type_carburant, boite_vitesse, ville_car, disponible, duree_mini_en_jour )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
    `;
    db.query(
      insertSql,
      [req.user.agence_id, marque, modele, annee, prix_par_jour, photo, type_carburant, boite_vitesse, ville_car, duree_mini_en_jour],
      (err2, result) => {
        if (err2) {
          console.error("Erreur ajout voiture:", err2);
          return res.status(500).json({ error: "Erreur serveur" });
        }
        res.status(201).json({ message: "Voiture ajoutée", result });
      }
    );
  });
});


// ----------------------------
// Modifier une voiture (uniquement si appartient à l'agence connectée)
// ----------------------------
app.put("/api/cars/:id", authenticateToken, (req, res) => {
  if (req.user.typeUser !== "agence")
    return res.status(403).json({ error: "Réservé aux agences" });

  const carId = req.params.id;
  const { marque, modele, annee, prix_par_jour, photo, disponible, type_carburant, boite_vitesse, ville_car, duree_mini_en_jour } = req.body;

  const checkSql = "SELECT * FROM cars WHERE id = ? AND agence_id = ?";
  db.query(checkSql, [carId, req.user.agence_id], (err, rows) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    if (rows.length === 0) return res.status(403).json({ error: "Non autorisé" });

    const updateSql = `
      UPDATE cars
      SET marque=?, modele=?, annee=?, prix_par_jour=?, photo=?, disponible=?, type_carburant=?, boite_vitesse=?, ville_car=?, duree_mini_en_jour=?
      WHERE id=? AND agence_id=?
    `;
    db.query(
      updateSql,
      [marque, modele, annee, prix_par_jour, photo, disponible, type_carburant, boite_vitesse, ville_car, duree_mini_en_jour, carId, req.user.agence_id],
      (err2) => {
        if (err2) return res.status(500).json({ error: "Erreur mise à jour" });
        res.json({ message: "Voiture modifiée" });
      }
    );
  });
});


// ----------------------------
// Ajouter une photo supplémentaire
// ----------------------------
// ----------------------------
// Ajouter une photo supplémentaire
// ----------------------------
app.post("/api/cars/:id/photos", authenticateToken, (req, res) => {
  if (req.user.typeUser !== "agence")
    return res.status(403).json({ error: "Réservé aux agences" });

  const carId = req.params.id;
  const { photoSuppl } = req.body;

  // Vérifier que la voiture appartient bien à cette agence
  const checkSql = "SELECT * FROM cars WHERE id = ? AND agence_id = ?";
  db.query(checkSql, [carId, req.user.agence_id], (err, rows) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    if (rows.length === 0) return res.status(403).json({ error: "Non autorisé" });

    // ✅ Insérer avec agence_id et car_id
    const insertSql = "INSERT INTO photossupplemetairs (agence_id, car_id, photoSuppl) VALUES (?, ?, ?)";
    db.query(insertSql, [req.user.agence_id, carId, photoSuppl], (err2, result) => {
      if (err2) return res.status(500).json({ error: "Erreur ajout photo" });

      res.status(201).json({
        message: "Photo ajoutée",
        photoRecord: {
          id: result.insertId,
          agence_id: req.user.agence_id,
          car_id: carId,
          photoSuppl
        }
      });
    });
  });
});


// ----------------------------
// Supprimer une photo supplémentaire
// ----------------------------
app.delete("/api/cars/:id/photos/:photoId", authenticateToken, (req, res) => {
  if (req.user.typeUser !== "agence")
    return res.status(403).json({ error: "Réservé aux agences" });

  const { id: carId, photoId } = req.params;

  // Vérif que la voiture appartient à l’agence
  const checkSql = "SELECT * FROM cars WHERE id = ? AND agence_id = ?";
  db.query(checkSql, [carId, req.user.agence_id], (err, rows) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    if (rows.length === 0) return res.status(403).json({ error: "Non autorisé" });

    const delSql = "DELETE FROM photossupplemetairs WHERE id = ? AND car_id = ?";
    db.query(delSql, [photoId, carId], (err2) => {
      if (err2) return res.status(500).json({ error: "Erreur suppression photo" });
      res.json({ message: "Photo supprimée" });
    });
  });
});

// Nouvelle route pour voiture + photos + agence utilisée dans détails car
app.get("/api/cars/:id/details", (req, res) => {
  const carId = req.params.id;

  const sqlCar = `
    SELECT cars.*, agences.nom AS agence_nom, agences.email AS agence_email,
           agences.telephone AS agence_tel, agences.ville AS agence_ville, agences.avatar AS agence_avatar
    FROM cars
    INNER JOIN agences ON cars.agence_id = agences.id
    WHERE cars.id = ?
  `;
  db.query(sqlCar, [carId], (err, rows) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    if (rows.length === 0) return res.status(404).json({ error: "Voiture introuvable" });

    const car = rows[0];
    const sqlPhotos = "SELECT id, photoSuppl FROM photossupplemetairs WHERE car_id = ?";
    db.query(sqlPhotos, [carId], (err2, photos) => {
      if (err2) return res.status(500).json({ error: "Erreur chargement photos" });
      car.photos = photos;
      res.json(car);
    });
  });
});

// Supprimer une voiture (et ses photos)
// ----------------------------
app.delete("/api/cars/:id", authenticateToken, (req, res) => {
  if (req.user.typeUser !== "agence")
    return res.status(403).json({ error: "Réservé aux agences" });

  const carId = req.params.id;

  // Vérifier que la voiture appartient à l’agence
  const checkSql = "SELECT * FROM cars WHERE id = ? AND agence_id = ?";
  db.query(checkSql, [carId, req.user.agence_id], (err, rows) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    if (rows.length === 0) return res.status(403).json({ error: "Non autorisé" });

    // Supprimer d’abord les photos supplémentaires
    const deletePhotos = "DELETE FROM photossupplemetairs WHERE car_id = ?";
    db.query(deletePhotos, [carId], (err2) => {
      if (err2) return res.status(500).json({ error: "Erreur suppression photos" });

      // Puis supprimer la voiture
      const deleteCar = "DELETE FROM cars WHERE id = ? AND agence_id = ?";
      db.query(deleteCar, [carId, req.user.agence_id], (err3) => {
        if (err3) return res.status(500).json({ error: "Erreur suppression voiture" });
        res.json({ message: "Voiture supprimée" });
      });
    });
  });
});

// Modifier disponibilité d'une voiture

app.put("/api/cars/:id/availability", authenticateToken, (req, res) => {
  if (req.user.typeUser !== "agence")
    return res.status(403).json({ error: "Réservé aux agences" });

  const carId = req.params.id;
  const { disponible } = req.body;

  const checkSql = "SELECT * FROM cars WHERE id = ? AND agence_id = ?";
  db.query(checkSql, [carId, req.user.agence_id], (err, rows) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    if (rows.length === 0) return res.status(403).json({ error: "Non autorisé" });

    const updateSql = "UPDATE cars SET disponible=? WHERE id=? AND agence_id=?";
    db.query(updateSql, [disponible, carId, req.user.agence_id], (err2) => {
      if (err2) return res.status(500).json({ error: "Erreur mise à jour" });
      res.json({ message: "Disponibilité mise à jour" });
    });
  });
});


// Récupérer infos agence connectée
app.get("/api/agences/me", authenticateToken, (req, res) => {
  if (req.user.typeUser !== "agence")
    return res.status(403).json({ error: "Réservé aux agences" });

  const sql = "SELECT id, nom, email, telephone, ville, avatar FROM agences WHERE id = ?";
  db.query(sql, [req.user.agence_id], (err, rows) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    if (rows.length === 0) return res.status(404).json({ error: "Agence introuvable" });
    res.json(rows[0]);
  });
});


// Modifier infos agence connectée
app.put("/api/agences/me", authenticateToken, (req, res) => {
  if (req.user.typeUser !== "agence")
    return res.status(403).json({ error: "Réservé aux agences" });

  const { nom, email, telephone, ville, avatar } = req.body;

  const sql = `
    UPDATE agences
    SET nom=?, email=?, telephone=?, ville=?, avatar=?
    WHERE id=?`;
  db.query(sql, [nom, email, telephone, ville, avatar, req.user.agence_id], (err, result) => {
    if (err) return res.status(500).json({ error: "Erreur mise à jour" });
    res.json({ message: "Profil agence modifié avec succès" });
  });
});


app.put("/api/agences/change-password", authenticateToken, (req, res) => {
  const { password, newPassword } = req.body;

  if (!password || !newPassword) {
    return res.status(400).json({ error: "Champs manquants." });
  }

  const agenceId = req.user.id;

  // 1. Vérifier si l’agence existe
  db.query("SELECT * FROM agences WHERE id = ?", [agenceId], (err, rows) => {
    if (err) {
      console.error("Erreur SELECT :", err);
      return res.status(500).json({ error: "Erreur serveur." });
    }

    if (rows.length === 0) {
      return res.status(404).json({ error: "Agence non trouvée." });
    }

    const agence = rows[0];

    // 2. Vérifier ancien mot de passe
    bcrypt.compare(password, agence.password, async (err, isMatch) => {
      if (err) {
        console.error("Erreur bcrypt.compare :", err);
        return res.status(500).json({ error: "Erreur serveur." });
      }

      if (!isMatch) {
        return res
          .status(401)
          .json({ error: "Ancien mot de passe incorrect." });
      }

      try {
        // 3. Hasher le nouveau mot de passe
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // 4. Mettre à jour dans agences
        db.query(
          "UPDATE agences SET password = ? WHERE id = ?",
          [hashedPassword, agenceId],
          (err) => {
            if (err) {
              console.error("Erreur UPDATE agences :", err);
              return res.status(500).json({ error: "Erreur serveur agences." });
            }

            // 5. Mettre aussi à jour dans users
            db.query(
              "UPDATE users SET password = ? WHERE agence_id = ?",
              [hashedPassword, agenceId],
              (err) => {
                if (err) {
                  console.error("Erreur UPDATE users :", err);
                  return res.status(500).json({ error: "Erreur serveur users." });
                }

                res.json({
                  message: "Mot de passe modifié avec succès ✅ (agence + user)",
                });
              }
            );
          }
        );
      } catch (hashErr) {
        console.error("Erreur hash :", hashErr);
        res.status(500).json({ error: "Erreur serveur hash." });
      }
    });
  });
});

// 1️⃣ MOT DE PASSE OUBLIÉ → envoi du lien par e-mail
//---------------------------------------------------------------
app.post("/api/forgot-password", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email requis" });

  // Vérifier si cet email correspond à un utilisateur existant
  const sql = `
    SELECT u.id, u.username, a.email AS agenceEmail
    FROM users u
    LEFT JOIN agences a ON u.agence_id = a.id
    WHERE u.username = ? OR a.email = ?
  `;

  db.query(sql, [email, email], (err, results) => {
    if (err) {
      console.error("Erreur SQL:", err);
      return res.status(500).json({ message: "Erreur serveur" });
    }

    if (results.length === 0)
      return res.status(404).json({ message: "Aucun compte trouvé avec cet e-mail." });

    const user = results[0];
    const userEmail = user.agenceEmail || user.username;

    // Générer un token JWT temporaire (valable 15 minutes)
    const resetToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: "15m",
    });

    // Créer le lien de réinitialisation (frontend)
    const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

    // Préparer l’e-mail
    const subject = "🔒 Réinitialisation de votre mot de passe - LOCA CAR";
    const logoUrl = `${process.env.FRONTEND_URL}/logo.png`;

    const html = `
      <div style="font-family: Arial, sans-serif; background-color: #f6f9fc; padding: 30px;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
          <div style="background-color: #0052cc; padding: 25px; text-align: center;">
            <img src="${logoUrl}" alt="LOCA CAR" style="width: 90px; height: auto; margin-bottom: 10px;" />
            <h1 style="color: #ffffff; margin: 0;">LOCA CAR</h1>
          </div>
          <div style="padding: 30px;">
            <h2 style="color: #333; text-align:center;">Réinitialisation du mot de passe</h2>
            <p style="font-size: 15px; color: #555;">
              Bonjour <strong>${user.username}</strong>,
            </p>
            <p style="font-size: 15px; color: #555;">
              Vous avez demandé à réinitialiser votre mot de passe.
              Cliquez sur le bouton ci-dessous pour le faire.
            </p>
            <div style="text-align: center; margin: 30px 0;">
              <a href="${resetLink}"
                style="background-color: #0052cc; color: white; text-decoration: none;
                      padding: 12px 25px; border-radius: 5px; display: inline-block; font-weight: bold;">
                🔑 Réinitialiser mon mot de passe
              </a>
            </div>
            <p style="font-size: 14px; color: #888;">
              Ce lien expirera dans <strong>15 minutes</strong> pour des raisons de sécurité.
            </p>
            <p style="font-size: 14px; color: #888;">
              Si vous n'êtes pas à l'origine de cette demande, vous pouvez ignorer cet e-mail.
            </p>
            <hr style="border:none; border-top:1px solid #eee; margin: 30px 0;">
            <p style="font-size: 12px; color: #999; text-align: center;">
              © ${new Date().getFullYear()} LOCA CAR —
              <a href="${process.env.FRONTEND_URL}" style="color:#0052cc; text-decoration:none;">Visitez notre site</a><br>
              Assistance : <a href="mailto:${process.env.EMAIL_USER}" style="color:#0052cc;">${process.env.EMAIL_USER}</a>
            </p>
          </div>
        </div>
      </div>
    `;

    // Envoi de l’e-mail
    sendEmail(userEmail, subject, "Réinitialisation de mot de passe", [], html);

    res.json({
      message: "Un lien de réinitialisation a été envoyé à votre adresse e-mail.",
    });
  });
});


//---------------------------------------------------------------
// 2️⃣ RÉINITIALISER LE MOT DE PASSE (via le lien reçu par e-mail)
//---------------------------------------------------------------
app.post("/api/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  if (!password)
    return res.status(400).json({ message: "Nouveau mot de passe requis." });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const hashedPassword = await bcrypt.hash(password, 10);

    // Mettre à jour le mot de passe dans les deux tables
    const updateUserSql = "UPDATE users SET password = ? WHERE id = ?";
    db.query(updateUserSql, [hashedPassword, decoded.id], (err) => {
      if (err) {
        console.error("Erreur UPDATE users:", err);
        return res.status(500).json({ message: "Erreur serveur (users)." });
      }

      // Synchroniser avec la table agences (si applicable)
      const updateAgenceSql = `
        UPDATE agences SET password = ?
        WHERE id = (SELECT agence_id FROM users WHERE id = ?)
      `;
      db.query(updateAgenceSql, [hashedPassword, decoded.id], (err2) => {
        if (err2) {
          console.error("Erreur UPDATE agences:", err2);
          // pas bloquant, car le compte user est déjà mis à jour
        }

        res.json({
          message: "Mot de passe réinitialisé avec succès ✅",
        });
      });
    });
  } catch (error) {
    console.error("Erreur reset token:", error);
    res.status(400).json({ message: "Lien invalide ou expiré." });
  }
});



// ==================== PROFIL AGENCE PUBLIC ====================

// GET infos d’une agence par son id
app.get("/api/agences/:id", (req, res) => {
  const { id } = req.params;
  const sql = `
    SELECT id, nom AS agence_nom, email AS agence_email,
           telephone AS agence_tel, ville AS agence_ville, avatar AS agence_avatar
    FROM agences
    WHERE id = ?
  `;
  db.query(sql, [id], (err, rows) => {
    if (err) {
      console.error("Erreur récupération agence:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    if (rows.length === 0) return res.status(404).json({ error: "Agence introuvable" });
    res.json(rows[0]);
  });
});

// GET toutes les voitures publiques d’une agence (avec photos sup)
app.get("/api/agences/:id/cars", (req, res) => {
  const { id } = req.params;

  const sqlCars = `
    SELECT
      c.id, c.agence_id, c.marque, c.modele, c.annee,
      c.prix_par_jour, c.photo, c.disponible,
      c.type_carburant, c.boite_vitesse, c.ville_car,
      c.duree_mini_en_jour, c.created_at
    FROM cars c
    WHERE c.agence_id = ?
    ORDER BY c.created_at DESC
  `;

  db.query(sqlCars, [id], (err, cars) => {
    if (err) {
      console.error("Erreur récupération voitures agence:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    if (!cars.length) return res.json([]);

    const carIds = cars.map((c) => c.id);
    const sqlPhotos = `
      SELECT car_id, photoSuppl
      FROM photossupplemetairs
      WHERE car_id IN (${carIds.map(() => "?").join(",")})
    `;

    db.query(sqlPhotos, carIds, (err2, photos) => {
      if (err2) {
        console.error("Erreur récupération photos suppl:", err2);
        // renvoie quand même sans photos suppl
        return res.json(cars.map((c) => ({ ...c, photos: c.photo ? [c.photo] : [] })));
      }

      // grouper les photos par car_id
      const photosByCar = {};
      photos.forEach((p) => {
        if (!photosByCar[p.car_id]) photosByCar[p.car_id] = [];
        photosByCar[p.car_id].push(p.photoSuppl);
      });

      const result = cars.map((c) => ({
        ...c,
        photos: [
          ...(c.photo ? [c.photo] : []),
          ...(photosByCar[c.id] || [])
        ].filter(Boolean)
      }));

      res.json(result);
    });
  });
});

app.get("/api/modeles", (req, res) => {
  const sql = "SELECT * FROM modelesParMarque ORDER BY marque ASC, modele ASC";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Erreur récupération modèles:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    res.json(results);
  });
});

// Carburants
app.get("/api/carburants", (req, res) => {
  const sql = "SELECT * FROM carburants ORDER BY carburant ASC";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Erreur récupération carburants:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    res.json(results);
  });
});

// Transmissions
app.get("/api/transmissions", (req, res) => {
  const sql = "SELECT * FROM transmissions ORDER BY transmission ASC";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Erreur récupération transmissions:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    res.json(results);
  });
});




// GET toutes les marques
app.get("/api/marques", (req, res) => {
  const sql = "SELECT * FROM marques ORDER BY marque ASC";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Erreur récupération marques:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    res.json(results);
  });
});

// GET toutes les villes
app.get("/api/villes", (req, res) => {
  const sql = "SELECT * FROM villes ORDER BY ville ASC";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Erreur récupération villes:", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    res.json(results);
  });
});



app.get('/', (req, res) => {
  res.send('Hello World!');
});

module.exports = app;

{/*app.listen(3001, () => {
  console.log('Server is running on the port 3001');
});*/}
