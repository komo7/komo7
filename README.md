import React, { useEffect, useState } from 'react';
import { Bar } from 'react-chartjs-2';

const Dashboard = () => {
  const [data, setData] = useState({});
  const [notifications, setNotifications] = useState([]);

  useEffect(() => {
    // Exemple de données pour les graphiques
    const chartData = {
      labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
      datasets: [
        {
          label: 'Revenus',
          backgroundColor: 'rgba(75,192,192,0.4)',
          borderColor: 'rgba(75,192,192,1)',
          borderWidth: 1,
          hoverBackgroundColor: 'rgba(75,192,192,0.6)',
          hoverBorderColor: 'rgba(75,192,192,1)',
          data: [65, 59, 80, 81, 56, 55],
        },
      ],
    };

    setData(chartData);

    // Exemple de notifications
    const sampleNotifications = [
      { id: 1, message: 'Échéance de facture le 15 février.', date: '2023-02-10' },
      { id: 2, message: 'Nouvelle dépense enregistrée.', date: '2023-02-12' },
    ];

    setNotifications(sampleNotifications);
  }, []); // Simule la récupération des données lors du chargement du composant

  return (
    <div>
      <h2>Tableau de Bord</h2>

      <div>
        <h3>Graphique des Revenus</h3>
        <Bar data={data} />
      </div>

      <div>
        <h3>Notifications</h3>
        <ul>
          {notifications.map((notification) => (
            <li key={notification.id}>{notification.message}</li>
          ))}
        </ul>
      </div>
    </div>
  );
};

export default Dashboard;
const express = require('express');
const http = require('http');
const WebSocket = require('ws');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  console.log('Client connecté');

  // Simule l'envoi de notifications chaque seconde
  const interval = setInterval(() => {
    ws.send(JSON.stringify({ message: 'Notification en temps réel !' }));
  }, 1000);

  ws.on('close', () => {
    console.log('Client déconnecté');
    clearInterval(interval);
  });
});

server.listen(3001, () => {
  console.log('Serveur WebSocket en écoute sur le port 3001');
});
import React, { useState } from 'react';
import axios from 'axios';

const Facturation = () => {
  const [nouvelleFacture, setNouvelleFacture] = useState({
    client: '',
    montant: 0,
  });

  const creerNouvelleFacture = async () => {
    try {
      const response = await axios.post('http://localhost:3001/api/factures', nouvelleFacture);
      console.log('Facture créée avec succès', response.data);
    } catch (error) {
      console.error('Erreur lors de la création de la facture', error);
    }
  };

  return (
    <div>
      <h2>Facturation</h2>
      <form>
        <label>
          Client:
          <input
            type="text"
            value={nouvelleFacture.client}
            onChange={(e) => setNouvelleFacture({ ...nouvelleFacture, client: e.target.value })}
          />
        </label>
        <br />
        <label>
          Montant:
          <input
            type="number"
            value={nouvelleFacture.montant}
            onChange={(e) => setNouvelleFacture({ ...nouvelleFacture, montant: e.target.value })}
          />
        </label>
        <br />
        <button type="button" onClick={creerNouvelleFacture}>
          Créer Facture
        </button>
      </form>
    </div>
  );
};

export default Facturation;
const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost:27017/comptagere', { useNewUrlParser: true, useUnifiedTopology: true });

const db = mongoose.connection;

db.on('error', console.error.bind(console, 'Erreur de connexion à MongoDB :'));
db.once('open', () => {
  console.log('Connecté à la base de données MongoDB');
});
const mongoose = require('mongoose');

const factureSchema = new mongoose.Schema({
  client: String,
  montant: Number,
  statutPaiement: { type: String, default: 'En attente' },
});

const Facture = mongoose.model('Facture', factureSchema);

module.exports = Facture;
const express = require('express');
const Facture = require('../models/facture');

const router = express.Router();

router.post('/', async (req, res) => {
  try {
    const nouvelleFacture = new Facture(req.body);
    await nouvelleFacture.save();

    res.json({ message: 'Facture créée avec succès' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la création de la facture' });
  }
});

module.exports = router;
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./db');
const facturesRoute = require('./routes/facturesRoute');

const app = express();
const port = 3001;

app.use(cors());
app.use(bodyParser.json());

app.use('/api/factures', facturesRoute);

app.listen(port, () => {
  console.log(`Serveur en cours d'exécution sur le port ${port}`);
});
import React, { useState } from 'react';
import axios from 'axios';

const GestionDepenses = () => {
  const [nouvelleDepense, setNouvelleDepense] = useState({
    description: '',
    montant: 0,
    categorie: '',
    image: null,
  });

  const creerNouvelleDepense = async () => {
    try {
      const formData = new FormData();
      formData.append('description', nouvelleDepense.description);
      formData.append('montant', nouvelleDepense.montant);
      formData.append('categorie', nouvelleDepense.categorie);
      formData.append('image', nouvelleDepense.image);

      const response = await axios.post('http://localhost:3001/api/depenses', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      console.log('Dépense créée avec succès', response.data);
    } catch (error) {
      console.error('Erreur lors de la création de la dépense', error);
    }
  };

  return (
    <div>
      <h2>Gestion des Dépenses</h2>
      <form>
        <label>
          Description:
          <input
            type="text"
            value={nouvelleDepense.description}
            onChange={(e) => setNouvelleDepense({ ...nouvelleDepense, description: e.target.value })}
          />
        </label>
        <br />
        <label>
          Montant:
          <input
            type="number"
            value={nouvelleDepense.montant}
            onChange={(e) => setNouvelleDepense({ ...nouvelleDepense, montant: e.target.value })}
          />
        </label>
        <br />
        <label>
          Catégorie:
          <input
            type="text"
            value={nouvelleDepense.categorie}
            onChange={(e) => setNouvelleDepense({ ...nouvelleDepense, categorie: e.target.value })}
          />
        </label>
        <br />
        <label>
          Image (Reçu numérique):
          <input
            type="file"
            accept="image/*"
            onChange={(e) => setNouvelleDepense({ ...nouvelleDepense, image: e.target.files[0] })}
          />
        </label>
        <br />
        <button type="button" onClick={creerNouvelleDepense}>
          Créer Dépense
        </button>
      </form>
    </div>
  );
};

export default GestionDepenses;
const mongoose = require('mongoose');

const depenseSchema = new mongoose.Schema({
  description: String,
  montant: Number,
  categorie: String,
  image: String, // Stocker le chemin de l'image, vous pouvez également utiliser GridFS pour stocker l'image directement dans MongoDB
});

const Depense = mongoose.model('Depense', depenseSchema);

module.exports = Depense;
const express = require('express');
const multer = require('multer');
const path = require('path');
const Depense = require('../models/depense');

const router = express.Router();

// Configuration de Multer pour gérer les fichiers
const storage = multer.diskStorage({
  destination: './uploads',
  filename: (req, file, cb) => {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ storage });

router.post('/', upload.single('image'), async (req, res) => {
  try {
    const nouvelleDepense = new Depense({
      description: req.body.description,
      montant: req.body.montant,
      categorie: req.body.categorie,
      image: req.file ? req.file.filename : null,
    });

    await nouvelleDepense.save();

    res.json({ message: 'Dépense créée avec succès' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la création de la dépense' });
  }
});

module.exports = router;
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./db');
const depensesRoute = require('./routes/depensesRoute');

const app = express();
const port = 3001;

app.use(cors());
app.use(bodyParser.json());

app.use('/api/depenses', depensesRoute);

app.listen(port, () => {
  console.log(`Serveur en cours d'exécution sur le port ${port}`);
});
const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  description: String,
  montant: Number,
  date: Date,
  rapproche: { type: Boolean, default: false },
});

const Transaction = mongoose.model('Transaction', transactionSchema);

module.exports = Transaction;
const express = require('express');
const axios = require('axios');
const Transaction = require('../models/transaction');

const router = express.Router();

// Simuler une requête à une API bancaire (exemple fictif)
const API_BANCAIRE_URL = 'https://api-bancaire-fictive.com/transactions';

router.get('/rapprochement-auto', async (req, res) => {
  try {
    // Récupérer toutes les transactions non rapprochées depuis la base de données
    const transactionsNonRapprochees = await Transaction.find({ rapproche: false });

    // Simuler une requête à l'API bancaire pour récupérer les transactions récentes
    const response = await axios.get(API_BANCAIRE_URL);

    // Filtrer les transactions de l'API qui ne sont pas encore rapprochées
    const nouvellesTransactions = response.data.filter((transaction) => {
      return !transactionsNonRapprochees.some(
        (t) => t.description === transaction.description && t.montant === transaction.montant
      );
    });

    // Créer de nouvelles transactions dans la base de données
    await Transaction.insertMany(
      nouvellesTransactions.map((transaction) => ({
        description: transaction.description,
        montant: transaction.montant,
        date: new Date(transaction.date),
      }))
    );

    res.json({ message: 'Rapprochement automatique effectué avec succès' });
  } catch (error) {
    console.error('Erreur lors du rapprochement automatique', error);
    res.status(500).json({ error: 'Erreur lors du rapprochement automatique' });
  }
});

module.exports = router;
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./db');
const depensesRoute = require('./routes/depensesRoute');
const rapprochementRoute = require('./routes/rapprochementRoute');

const app = express();
const port = 3001;

app.use(cors());
app.use(bodyParser.json());

app.use('/api/depenses', depensesRoute);
app.use('/api/rapprochement', rapprochementRoute); // Nouvelle route pour le rapprochement bancaire

app.listen(port, () => {
  console.log(`Serveur en cours d'exécution sur le port ${port}`)
  const express = require('express');
const axios = require('axios');
const Transaction = require('../models/transaction');

const router = express.Router();

// Simuler une requête à une API bancaire (exemple fictif)
const API_BANCAIRE_URL = 'https://api-bancaire-fictive.com/transactions';

router.get('/rapprochement-auto', async (req, res) => {
  try {
    // Récupérer toutes les transactions non rapprochées depuis la base de données
    const transactionsNonRapprochees = await Transaction.find({ rapproche: false });

    // Simuler une requête à l'API bancaire pour récupérer les transactions récentes
    const response = await axios.get(API_BANCAIRE_URL);

    // Filtrer les transactions de l'API qui ne sont pas encore rapprochées
    const nouvellesTransactions = response.data.filter((transaction) => {
      return !transactionsNonRapprochees.some(
        (t) => t.description === transaction.description && t.montant === transaction.montant
      );
    });

    // Créer de nouvelles transactions dans la base de données
    await Transaction.insertMany(
      nouvellesTransactions.map((transaction) => ({
        description: transaction.description,
        montant: transaction.montant,
        date: new Date(transaction.date),
      }))
    );

    // Marquer les transactions comme rapprochées dans la base de données
    await Transaction.updateMany(
      { description: { $in: nouvellesTransactions.map((t) => t.description) } },
      { $set: { rapproche: true } }
    );

    res.json({ message: 'Rapprochement automatique effectué avec succès' });
  } catch (error) {
    console.error('Erreur lors du rapprochement automatique', error);
    res.status(500).json({ error: 'Erreur lors du rapprochement automatique' });
  }
});

module.exports = router;
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./db');
const depensesRoute = require('./routes/depensesRoute');
const rapprochementRoute = require('./routes/rapprochementRoute');

const app = express();
const port = 3001;

app.use(cors());
app.use(bodyParser.json());

app.use('/api/depenses', depensesRoute);
app.use('/api/rapprochement', rapprochementRoute); // Nouvelle route pour le rapprochement bancaire

app.listen(port, () => {
  console.log(`Serveur en cours d'exécution sur le port ${port}`);
});
const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  description: String,
  montant: Number,
  date: Date,
  rapproche: { type: Boolean, default: false },
});

const Transaction = mongoose.model('Transaction', transactionSchema);

module.exports = Transaction;
const express = require('express');
const axios = require('axios');
const Transaction = require('../models/transaction');

const router = express.Router();

// Remplacez cette URL par l'URL réelle de l'API bancaire
const API_BANCAIRE_URL = 'https://api-bancaire-fictive.com/transactions';

router.get('/rapprochement-auto', async (req, res) => {
  try {
    // Récupérer toutes les transactions non rapprochées depuis la base de données
    const transactionsNonRapprochees = await Transaction.find({ rapproche: false });

    // Simuler une requête à l'API bancaire pour récupérer les transactions récentes
    const response = await axios.get(API_BANCAIRE_URL);

    // Filtrer les transactions de l'API qui ne sont pas encore rapprochées
    const nouvellesTransactions = response.data.filter((transaction) => {
      return !transactionsNonRapprochees.some(
        (t) => t.description === transaction.description && t.montant === transaction.montant
      );
    });

    // Créer de nouvelles transactions dans la base de données
    await Transaction.insertMany(
      nouvellesTransactions.map((transaction) => ({
        description: transaction.description,
        montant: transaction.montant,
        date: new Date(transaction.date),
      }))
    );

    // Marquer les transactions comme rapprochées dans la base de données
    await Transaction.updateMany(
      { description: { $in: nouvellesTransactions.map((t) => t.description) } },
      { $set: { rapproche: true } }
    );

    res.json({ message: 'Rapprochement automatique effectué avec succès' });
  } catch (error) {
    console.error('Erreur lors du rapprochement automatique', error);
    res.status(500).json({ error: 'Erreur lors du rapprochement automatique' });
  }
});

module.exports = router;
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./db');
const depensesRoute = require('./routes/depensesRoute');
const rapprochementRoute = require('./routes/rapprochementRoute');

const app = express();
const port = 3001;

app.use(cors());
app.use(bodyParser.json());

app.use('/api/depenses', depensesRoute);
app.use('/api/rapprochement', rapprochementRoute); // Nouvelle route pour le rapprochement bancaire

app.listen(port, () => {
  console.log(`Serveur en cours d'exécution sur le port ${port}`);
});
const mongoose = require('mongoose');

const factureRecurrenteSchema = new mongoose.Schema({
  client: String,
  montant: Number,
  frequence: String, // 'mensuel', 'trimestriel', etc.
  prochaineEcheance: Date,
});

const FactureRecurrente = mongoose.model('FactureRecurrente', factureRecurrenteSchema);

module.exports = FactureRecurrente;
const cron = require('node-cron');
const FactureRecurrente = require('../models/factureRecurrente');
const Facture = require('../models/facture');

// Planifier la génération automatique des factures récurrentes
cron.schedule('0 0 * * *', async () => {
  try {
    // Récupérer toutes les factures récurrentes dont la prochaine échéance est aujourd'hui
    const facturesRecurrentes = await FactureRecurrente.find({
      prochaineEcheance: { $lte: new Date() },
    });

    // Générer les nouvelles factures et mettre à jour la prochaine échéance
    await Promise.all(
      facturesRecurrentes.map(async (factureRecurrente) => {
        const nouvelleFacture = new Facture({
          client: factureRecurrente.client,
          montant: factureRecurrente.montant,
        });

        await nouvelleFacture.save();

        // Mettre à jour la prochaine échéance en fonction de la fréquence
        const prochaineEcheance = new Date(factureRecurrente.prochaineEcheance);
        switch (factureRecurrente.frequence) {
          case 'mensuel':
            prochaineEcheance.setMonth(prochaineEcheance.getMonth() + 1);
            break;
          // Ajoutez d'autres cas pour d'autres fréquences
        }

        await FactureRecurrente.findByIdAndUpdate(
          factureRecurrente._id,
          { prochaineEcheance },
          { new: true }
        );
      })
    );

    console.log('Génération automatique des factures récurrentes effectuée avec succès');
  } catch (error) {
    console.error('Erreur lors de la génération automatique des factures récurrentes', error);
  }
});

// Planifier l'envoi automatique des rappels pour les échéances importantes
cron.schedule('0 12 * * *', async () => {
  try {
    // Récupérer toutes les factures dont l'échéance est dans les 7 prochains jours
    const dateLimite = new Date();
    dateLimite.setDate(dateLimite.getDate() + 7);

    const facturesAvecEcheanceProche = await Facture.find({
      dateEcheance: { $lte: dateLimite },
      statut: 'En attente', // Assurez-vous que le statut correspond à une facture en attente de paiement
    });

    // Envoyer les rappels pour les factures avec échéance proche
    await Promise.all(
      facturesAvecEcheanceProche.map(async (facture) => {
        // Ici, vous pouvez intégrer l'envoi de rappels par e-mail, SMS, etc.
        console.log(`Envoyer rappel pour la facture ${facture._id} au client ${facture.client}`);
      })
    );

    console.log('Envoi automatique des rappels effectué avec succès');
  } catch (error) {
    console.error('Erreur lors de l\'envoi automatique des rappels', error);
  }
});
vconst mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  role: String, // 'comptable', 'administrateur', etc.
});

const User = mongoose.model('User', userSchema);

module.exports = User;
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/user');

const router = express.Router();

// Secret pour la signature du token (devrait être stocké de manière sécurisée dans un environnement de production)
const JWT_SECRET = 'votre_secret';

// Middleware pour vérifier le token JWT
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ message: 'Authorization header manquant' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token invalide' });
    req.user = user;
    next();
  });
};

router.post('/register', async (req, res) => {
  try {
    const { username, password, role } = req.body;

    // Vérifier si l'utilisateur existe déjà
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ message: 'Nom d\'utilisateur déjà utilisé' });

    // Hash du mot de passe avant de le stocker
    const hashedPassword = await bcrypt.hash(password, 10);

    // Créer un nouvel utilisateur
    const newUser = new User({
      username,
      password: hashedPassword,
      role,
    });

    await newUser.save();

    res.status(201).json({ message: 'Utilisateur enregistré avec succès' });
  } catch (error) {
    console.error('Erreur lors de l\'enregistrement de l\'utilisateur', error);
    res.status(500).json({ error: 'Erreur lors de l\'enregistrement de l\'utilisateur' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Vérifier si l'utilisateur existe
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ message: 'Nom d\'utilisateur ou mot de passe incorrect' });

    // Vérifier le mot de passe
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(401).json({ message: 'Nom d\'utilisateur ou mot de passe incorrect' });

    // Générer un token JWT
    const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET);

    res.json({ token });
  } catch (error) {
    console.error('Erreur lors de la connexion de l\'utilisateur', error);
    res.status(500).json({ error: 'Erreur lors de la connexion de l\'utilisateur' });
  }
});

module.exports = { router, authenticateJWT };
const mongoose = require('mongoose');

const taskSchema = new mongoose.Schema({
  description: String,
  assignee: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // L'utilisateur à qui la tâche est assignée
  completed: { type: Boolean, default: false },
});

const Task = mongoose.model('Task', taskSchema);

module.exports = Task;
const express = require('express');
const { authenticateJWT } = require('./auth');
const Task = require('../models/task');

const router = express.Router();

router.post('/create', authenticateJWT, async (req, res) => {
  try {
    const { description, assignee } = req.body;

    // Vérifier si l'utilisateur a le droit d'assigner des tâches (ex. rôle d'administrateur)
    if (req.user.role !== 'administrateur') {
      return res.status(403).json({ message: 'Accès non autorisé' });
    }

    // Créer une nouvelle tâche
    const newTask = new Task({
      description,
      assignee,
    });

    await newTask.save();

    res.status(201).json({ message: 'Tâche créée avec succès' });
  } catch (error) {
    console.error('Erreur lors de la création de la tâche', error);
    res.status(500).json({ error: 'Erreur lors de la création de la tâche' });
  }
});

router.get('/list', authenticateJWT, async (req, res) => {
  try {
    // Récupérer la liste des tâches assignées à l'utilisateur
    const tasks = await Task.find({ assignee: req.user._id });

    res.json(tasks);
  } catch (error) {
    console.error('Erreur lors de la récupération de la liste des tâches', error);
    res.status(500).json({ error: 'Erreur lors de la récupération de la liste des tâches' });
  }
});

module.exports = router;
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./db');
const authRoute = require('./routes/auth');
const tasksRoute = require('./routes/tasksRoute');

const app = express();
const port = 3001;

app.use(cors());
app.use(bodyParser.json());

app.use('/api/auth', authRoute.router);
app.use('/api/tasks', tasksRoute);

app.listen(port, () => {
  console.log(`Serveur en cours d'exécution sur le port ${port}`);
});
const crypto = require('crypto');

// Clé secrète pour le chiffrement (devrait être stockée de manière sécurisée dans un environnement de production)
const SECRET_KEY = 'votre_cle_secrete';

function encrypt(data) {
  const cipher = crypto.createCipher('aes-256-cbc', SECRET_KEY);
  let encrypted = cipher.update(data, 'utf-8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decrypt(encryptedData) {
  const decipher = crypto.createDecipher('aes-256-cbc', SECRET_KEY);
  let decrypted = decipher.update(encryptedData, 'hex', 'utf-8');
  decrypted += decipher.final('utf-8');
  return decrypted;
}

module.exports = { encrypt, decrypt };
const mongoose = require('mongoose');

const sensitiveDataSchema = new mongoose.Schema({
  // Chiffrez les données sensibles avant de les stocker
  numeroCarteCredit: String, // Exemple de données sensibles
});

const SensitiveData = mongoose.model('SensitiveData', sensitiveDataSchema);

module.exports = SensitiveData;
const express = require('express');
const { authenticateJWT } = require('./auth');
const { encrypt, decrypt } = require('./encryption');
const SensitiveData = require('../models/sensitiveData');

const router = express.Router();

router.post('/store', authenticateJWT, async (req, res) => {
  try {
    const { numeroCarteCredit } = req.body;

    // Chiffrez les données sensibles avant de les stocker
    const encryptedNumeroCarteCredit = encrypt(numeroCarteCredit);

    // Créer une nouvelle entrée pour les données sensibles
    const newSensitiveData = new SensitiveData({
      numeroCarteCredit: encryptedNumeroCarteCredit,
    });

    await newSensitiveData.save();

    res.status(201).json({ message: 'Données sensibles stockées avec succès' });
  } catch (error) {
    console.error('Erreur lors du stockage des données sensibles', error);
    res.status(500).json({ error: 'Erreur lors du stockage des données sensibles' });
  }
});

router.get('/retrieve', authenticateJWT, async (req, res) => {
  try {
    // Récupérer les données sensibles de l'utilisateur
    const sensitiveData = await SensitiveData.findOne();

    if (!sensitiveData) {
      return res.status(404).json({ message: 'Aucune donnée sensible trouvée' });
    }

    // Déchiffrez les données sensibles avant de les renvoyer
    const decryptedNumeroCarteCredit = decrypt(sensitiveData.numeroCarteCredit);

    res.json({ numeroCarteCredit: decryptedNumeroCarteCredit });
  } catch (error) {
    console.error('Erreur lors de la récupération des données sensibles', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des données sensibles' });
  }
});

module.exports = router;
// Ici, vous pouvez implémenter des fonctions pour vérifier la conformité aux normes comptables et fiscales locales
function checkCompliance() {
  // Vérifications de conformité spécifiques à votre domaine
  return true; // Retourne true si conforme, false sinon
}

module.exports = { checkCompliance };
const { checkCompliance } = require('./compliance');

function ensureCompliance(req, res, next) {
  if (checkCompliance()) {
    next();
  } else {
    res.status(403).json({ message: 'Non conforme aux normes comptables et fiscales locales' });
  }
}

module.exports = { ensureCompliance };
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./db');
const authRoute = require('./routes/auth');
const sensitiveDataRoute = require('./routes/sensitiveDataRoute');
const complianceMiddleware = require('./middleware/complianceMiddleware');

const app = express();
const port = 3001;

app.use(cors());
app.use(bodyParser.json());

app.use('/api/auth', authRoute.router);

// Utilisez le middleware pour la vérification de conformité sur les routes nécessitant une conformité
app.use('/api/sensitive-data', complianceMiddleware.ensureCompliance, sensitiveDataRoute);

app.listen(port, () => {
  console.log(`Serveur en cours d'exécution sur le port ${port}`);
});
const express = require('express');
const { authenticateJWT } = require('./auth');
const Facture = require('../models/facture');

const router = express.Router();

router.post('/creer', authenticateJWT, async (req, res) => {
  try {
    const { client, articles } = req.body;

    // Générer automatiquement un numéro de facture unique
    const numeroFacture = generateUniqueInvoiceNumber();

    // Créer une nouvelle facture
    const nouvelleFacture = new Facture({
      numero: numeroFacture,
      client,
      articles,
    });

    await nouvelleFacture.save();

    res.status(201).json({ message: 'Facture créée avec succès', numeroFacture });
  } catch (error) {
    console.error('Erreur lors de la création de la facture', error);
    res.status(500).json({ error: 'Erreur lors de la création de la facture' });
  }
});

// Fonction pour générer un numéro de facture unique
function generateUniqueInvoiceNumber() {
  // Logique pour générer un numéro de facture unique (à implémenter)
  return 'INV123456';
}

module.exports = router;
const express = require('express');
const { authenticateJWT } = require('./auth');
const Facture = require('../models/facture');

const router = express.Router();

router.get('/factures-en-attente', authenticateJWT, async (req, res) => {
  try {
    // Récupérer les factures en attente de paiement
    const facturesEnAttente = await Facture.find({ statut: 'En attente' });

    res.json(facturesEnAttente);
  } catch (error) {
    console.error('Erreur lors de la récupération des factures en attente', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des factures en attente' });
  }
});

// Endpoint pour les notifications de paiements en retard (à implémenter)
router.post('/notifications-paiements-en-retard', authenticateJWT, (req, res) => {
  // Logique pour envoyer des notifications (exemple : via un service de messagerie)
  res.json({ message: 'Notifications envoyées avec succès' });
});

module.exports = router;
import React, { useState } from 'react';
import axios from 'axios';

const CreateInvoice = () => {
  const [client, setClient] = useState('');
  const [articles, setArticles] = useState([]);

  const handleCreateInvoice = async () => {
    try {
      // Appel à l'API pour créer une nouvelle facture
      const response = await axios.post('/api/factures/creer', { client, articles });

      console.log(response.data.message);
      console.log('Numéro de facture:', response.data.numeroFacture);
    } catch (error) {
      console.error('Erreur lors de la création de la facture', error);
    }
  };

  return (
    <div>
      <h2>Créer une Facture</h2>
      <label>Client:</label>
      <input type="text" value={client} onChange={(e) => setClient(e.target.value)} />

      <label>Articles:</label>
      <textarea value={articles} onChange={(e) => setArticles(e.target.value)} />

      <button onClick={handleCreateInvoice}>Créer Facture</button>
    </div>
  );
};

export default CreateInvoice;
import React, { useEffect, useState } from 'react';
import axios from 'axios';

const PaymentDashboard = () => {
  const [facturesEnAttente, setFacturesEnAttente] = useState([]);

  useEffect(() => {
    // Appel à l'API pour récupérer les factures en attente
    const fetchFacturesEnAttente = async () => {
      try {
        const response = await axios.get('/api/tableau-de-bord/factures-en-attente');
        setFacturesEnAttente(response.data);
      } catch (error) {
        console.error('Erreur lors de la récupération des factures en attente', error);
      }
    };

    fetchFacturesEnAttente();
  }, []);

  return (
    <div>
      <h2>Tableau de Bord des Paiements</h2>
      <ul>
        {facturesEnAttente.map((facture) => (
          <li key={facture._id}>{facture.numero} - {facture.client}</li>
        ))}
      </ul>
    </div>
  );
};

export default PaymentDashboard;
