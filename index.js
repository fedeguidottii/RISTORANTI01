const express = require('express');
const multer = require('multer');
const cors = require('cors');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const QRCode = require('qrcode');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const cookieParser = require('cookie-parser');

// Sostituisci la require diretta di nodemailer con try/catch
let nodemailer=null, mailer=null;
try {
  nodemailer = require('nodemailer');
  // Inizializza solo se variabili SMTP presenti
  if (process.env.SMTP_HOST && process.env.SMTP_USER) {
    mailer = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: /^true$/i.test(process.env.SMTP_SECURE || 'false'),
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });
    console.log('Mailer attivo.');
  } else {
    console.log('Mailer inattivo: variabili SMTP mancanti.');
  }
} catch (err) {
  console.log('nodemailer non installato: email disabilitate (ok in ambienti senza mailing).');
}

// --- INIZIALIZZAZIONE FIREBASE ADMIN ---
try {
    const serviceAccount = require('./firebase-service-account.json');
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    console.log("Firebase Admin SDK inizializzato con successo.");
} catch (error) {
    console.error("ERRORE CRITICO: File 'firebase-service-account.json' non trovato o non valido.", error);
    process.exit(1);
}
const db = admin.firestore();

const app = express();

// --- SECURITY MIDDLEWARE ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://www.gstatic.com", "https://www.googletagmanager.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:", "blob:"],
            connectSrc: ["'self'", "https://*.firebaseio.com", "https://*.googleapis.com", "wss://*.firebaseio.com", "https://upload-beckend.onrender.com"]
        }
    }
}));

// --- CONFIGURAZIONE CORS ROBUSTA ---
app.use(cors({
    origin: true,
    credentials: true
}));
app.options('*', cors()); 
app.use(express.json());
app.use(cookieParser());

// --- RATE LIMITING ---
// Global rate limiter
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Troppe richieste da questo IP, riprova più tardi.'
});

// Strict rate limiter for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    skipSuccessfulRequests: true,
    message: 'Troppi tentativi di accesso. Riprova tra 15 minuti.'
});

// --- CONFIGURAZIONE CLOUDINARY ---
cloudinary.config({ 
  cloud_name: 'dyewzmvpa', 
  api_key: '245647176451857', 
  api_secret: 'cR-VWOp7lHX3kV6Wns_TuPm2MiM' 
});

// --- SETUP STORAGE PER UPLOAD IMMAGINI ---
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: (req, file) => {
    let folder = 'default';
    if (req.path.includes('/add-dish') || req.path.includes('/update-dish')) {
        folder = 'dish_images';
    } else if (req.path.includes('/create-restaurant') || req.path.includes('/update-restaurant') || req.path.includes('/update-restaurant-details')) {
        folder = 'logos';
    }
    
    return {
        folder: folder,
        allowed_formats: ['jpeg', 'png', 'jpg', 'webp'],
        transformation: [{ width: 500, height: 500, crop: 'limit' }]
    };
  },
});
const upload = multer({ storage: storage });

// --- FUNZIONE DI UTILITÀ PER LA CANCELLAZIONE RICORSIVA ---
async function deleteCollection(collectionRef, batchSize = 100) {
    const query = collectionRef.limit(batchSize);
    return new Promise((resolve, reject) => {
      deleteQueryBatch(query, resolve).catch(reject);
    });
  
    async function deleteQueryBatch(query, resolve) {
      const snapshot = await query.get();
      if (snapshot.size === 0) return resolve();
  
      const batch = db.batch();
      snapshot.docs.forEach(doc => batch.delete(doc.ref));
      await batch.commit();
  
      process.nextTick(() => deleteQueryBatch(query, resolve));
    }
}

// --- ROTTA PER GENERARE QR CODE ---
app.post('/generate-qr', async (req, res) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }
    try {
        const qrCodeDataUrl = await QRCode.toDataURL(url, {
            errorCorrectionLevel: 'H',
            type: 'image/png',
            margin: 2,
            color: { dark:"#000000", light:"#FFFFFF" }
        });
        // Removed undefined fields (totalGuests, dailyGuests, dailyAvgSpend) that caused 500
        return res.json({ success: true, qrCode: qrCodeDataUrl });
    } catch (err) {
        console.error('QR generation error:', err);
        return res.status(500).json({ error: 'Failed to generate QR code' });
    }
});

// --- ROTTE GESTIONE PRENOTAZIONI ---
app.post('/restaurants/:docId/reservations', async (req, res) => {
    const { docId } = req.params;
    const { customerName, customerPhone, partySize, tableId, tableName, dateTime, dinnerDuration } = req.body;

    if (!customerName || !partySize || !dateTime) {
        return res.status(400).json({ error: 'Nome, numero persone e data/ora sono obbligatori.' });
    }
    try {
        const docRef = await db.collection(`ristoranti/${docId}/prenotazioni`).add({
            customerName,
            customerPhone: customerPhone || '',
            partySize: Number(partySize),
            tableId: tableId || '',
            tableName: tableName || 'Non assegnato',
            dateTime: admin.firestore.Timestamp.fromDate(new Date(dateTime)),
            dinnerDuration: Number(dinnerDuration) || 90, // Store dinner duration in minutes
            status: 'confermata',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
        res.status(201).json({ success: true, id: docRef.id });
    } catch (error) {
        console.error('Error creating reservation:', error);
        res.status(500).json({ error: 'Errore interno del server.' });
    }
});

app.patch('/restaurants/:docId/reservations/:reservationId', async (req, res) => {
    const { docId, reservationId } = req.params;
    const { status } = req.body;
    if (!status) {
        return res.status(400).json({ error: 'Il nuovo stato è obbligatorio.' });
    }
    try {
        const resRef = db.collection(`ristoranti/${docId}/prenotazioni`).doc(reservationId);
        await resRef.update({ status: status });
        res.json({ success: true, message: 'Stato prenotazione aggiornato.' });
    } catch (error) {
        res.status(500).json({ error: 'Errore interno del server.' });
    }
});

app.put('/restaurants/:docId/reservations/:reservationId', async (req, res) => {
    const { docId, reservationId } = req.params;
    const { customerName, customerPhone, partySize, tableId, tableName, dateTime, dinnerDuration } = req.body;

    if (!customerName || !partySize || !dateTime) {
        return res.status(400).json({ error: 'Nome, numero persone e data/ora sono obbligatori.' });
    }
    try {
        const resRef = db.collection(`ristoranti/${docId}/prenotazioni`).doc(reservationId);
        const doc = await resRef.get();
        if (!doc.exists) {
            return res.status(404).json({ error: 'Prenotazione non trovata.' });
        }

        await resRef.update({
            customerName,
            customerPhone: customerPhone || '',
            partySize: Number(partySize),
            tableId: tableId || '',
            tableName: tableName || 'Non assegnato',
            dateTime: admin.firestore.Timestamp.fromDate(new Date(dateTime)),
            dinnerDuration: Number(dinnerDuration) || 90
        });
        return res.json({ success: true, message: 'Prenotazione aggiornata con successo.' });
    } catch (error) {
        console.error("Errore aggiornamento prenotazione:", error);
        res.status(500).json({ error: 'Errore interno del server.' });
    }
});

app.post('/restaurants/:docId/check-in/:reservationId', async (req, res) => {
    const { docId, reservationId } = req.params;
    try {
        const reservationRef = db.collection(`ristoranti/${docId}/prenotazioni`).doc(reservationId);
        
        const pin = String(Math.floor(1000 + Math.random() * 9000));
        let resultData = {};

        await db.runTransaction(async (t) => {
            const reservationDoc = await t.get(reservationRef);
            if (!reservationDoc.exists) throw new Error("Prenotazione non trovata.");
            
            const reservationData = reservationDoc.data();
            const { tableId, partySize } = reservationData;
            
            if (!tableId) throw new Error("Nessun tavolo assegnato a questa prenotazione.");

            const tableRef = db.collection(`ristoranti/${docId}/fixedTables`).doc(tableId);
            const tableDoc = await t.get(tableRef);
            if (!tableDoc.exists) throw new Error("Tavolo non trovato.");
            if (tableDoc.data().status === 'attivo') throw new Error("Il tavolo è già occupato.");

            t.update(reservationRef, { status: 'completata' });
            t.update(tableRef, {
                status: 'attivo',
                sessionPin: pin,
                guests: partySize,
                activatedAt: admin.firestore.FieldValue.serverTimestamp(),
                cart: [], orders: {}, orderHistory: [], paidAt: null, ordersSentCount: 0
            });
            resultData = { ...reservationData, pin };
        });

        res.json({ 
            success: true, 
            pin: resultData.pin, 
            tableName: resultData.tableName, 
            customerName: resultData.customerName 
        });

    } catch(error) {
        console.error("Errore durante il check-in:", error);
        res.status(400).json({ error: error.message });
    }
});

// ROTTA PER ORDINARE CATEGORIE
app.post('/update-categories-order/:restaurantId', async (req, res) => {
    const { restaurantId } = req.params;
    const { categoriesOrder } = req.body;

    if (!categoriesOrder || !Array.isArray(categoriesOrder)) {
        return res.status(400).json({ error: 'Ordine categorie non valido.' });
    }

    try {
        const batch = db.batch();
        categoriesOrder.forEach((categoryId, index) => {
            const catRef = db.collection(`ristoranti/${restaurantId}/menuCategories`).doc(categoryId);
            batch.update(catRef, { order: index });
        });
        await batch.commit();
        res.json({ success: true, message: 'Ordine categorie aggiornato!' });
    } catch (error) {
        console.error("Errore aggiornamento ordine categorie:", error);
        res.status(500).json({ error: 'Errore interno del server.' });
    }
});

// Nuovo endpoint per aggiornare una categoria (nome e stato)
app.put('/update-category/:restaurantId/:categoryId', async (req, res) => {
    const { restaurantId, categoryId } = req.params;
    const { name, isActive } = req.body;

    if (!name || typeof isActive !== 'boolean') {
        return res.status(400).json({ error: 'Nome e stato attivo sono obbligatori.' });
    }

    try {
        const categoryRef = db.collection(`ristoranti/${restaurantId}/menuCategories`).doc(categoryId);
        await categoryRef.update({ name, isActive });

        // Se la categoria viene disattivata, disattiva tutti i piatti in quella categoria
        if (!isActive) {
            const menuSnapshot = await db.collection(`ristoranti/${restaurantId}/menu`)
                .where('category', '==', name)
                .get();
            
            const batch = db.batch();
            menuSnapshot.docs.forEach(doc => {
                batch.update(doc.ref, { isAvailable: false });
            });
            await batch.commit();
        }

        res.json({ 
            success: true, 
            message: isActive ? 'Categoria aggiornata!' : 'Categoria e piatti associati disattivati!' 
        });
    } catch (error) {
        console.error("Errore aggiornamento categoria:", error);
        res.status(500).json({ error: 'Errore interno del server.' });
    }
});

// --- ROTTE GESTIONE PIATTI ---
app.post('/add-dish/:restaurantId', upload.single('photo'), async (req, res) => {
    const { restaurantId } = req.params;
    const { name, description, price, category } = req.body;
    const isExtraCharge = req.body.isExtraCharge === 'true';
    const allergens = req.body.allergens ? JSON.parse(req.body.allergens) : [];

    if (!name || !price || !category) {
        return res.status(400).json({ error: 'Nome, prezzo e categoria sono obbligatori.' });
    }

    try {
        // Get current maximum order value to append new dish at the end
        const menuSnapshot = await db.collection(`ristoranti/${restaurantId}/menu`).orderBy('order', 'desc').limit(1).get();
        const maxOrder = menuSnapshot.empty ? 0 : (menuSnapshot.docs[0].data().order || 0);

        const newDishData = {
            name,
            description: description || '',
            price: parseFloat(price),
            category,
            isAvailable: true,
            isSpecial: false,
            isExtraCharge,
            allergens,
            photoUrl: req.file ? req.file.path : null,
            order: maxOrder + 1, // Add order field for consistent positioning
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };

        const docRef = await db.collection(`ristoranti`).doc(restaurantId).collection('menu').add(newDishData);
        res.status(201).json({ success: true, message: 'Piatto aggiunto con successo!', dishId: docRef.id });

    } catch (error) {
        console.error('Error adding dish:', error);
        res.status(500).json({ error: 'Errore interno del server durante l\'aggiunta del piatto.' });
    }
});

app.post('/update-dish/:restaurantId/:dishId', upload.single('photo'), async (req, res) => {
    const { restaurantId, dishId } = req.params;
    const { name, description, price, category } = req.body;
    const isExtraCharge = req.body.isExtraCharge === 'true';
    const allergens = req.body.allergens ? JSON.parse(req.body.allergens) : [];

    try {
        const docRef = db.collection(`ristoranti/${restaurantId}/menu`).doc(dishId);
        const docSnap = await docRef.get();
        if (!docSnap.exists) return res.status(404).json({ error: 'Piatto non trovato.' });

        const updateData = {
            name, description, price: parseFloat(price), category,
            isExtraCharge,
            allergens
        };

        if (req.file) {
            const oldData = docSnap.data();
            if (oldData.photoUrl && oldData.photoUrl.includes('cloudinary')) {
                const publicId = oldData.photoUrl.split('/').pop().split('.')[0];
                const folder = oldData.photoUrl.includes('/dish_images/') ? 'dish_images' : 'logos';
                await cloudinary.uploader.destroy(`${folder}/${publicId}`);
            }
            updateData.photoUrl = req.file.path;
        }

        await docRef.update(updateData);
        res.json({ success: true, message: 'Piatto aggiornato!' });
    } catch (error) {
        res.status(500).json({ error: 'Errore durante l\'aggiornamento del piatto.' });
    }
});


// --- ROTTE DI LOGIN ---
// Input validation rules
const restaurantValidationRules = () => {
    return [
        body('nomeRistorante')
            .trim()
            .notEmpty().withMessage('Nome ristorante è obbligatorio')
            .isLength({ min: 2, max: 100 }).withMessage('Nome ristorante deve essere tra 2 e 100 caratteri')
            .matches(/^[a-zA-Z0-9\s\-'àèéìòùÀÈÉÌÒÙ]+$/).withMessage('Nome ristorante contiene caratteri non validi'),
        body('username')
            .trim()
            .notEmpty().withMessage('Username è obbligatorio')
            .isLength({ min: 3, max: 50 }).withMessage('Username deve essere tra 3 e 50 caratteri')
            .matches(/^[a-zA-Z0-9_-]+$/).withMessage('Username può contenere solo lettere, numeri, - e _'),
        body('password')
            .notEmpty().withMessage('Password è obbligatoria')
            .isLength({ min: 6 }).withMessage('Password deve essere almeno 6 caratteri')
            .matches(/^(?=.*[A-Za-z])(?=.*\d)/).withMessage('Password deve contenere almeno una lettera e un numero'),
        body('email')
            .trim()
            .notEmpty().withMessage('Email è obbligatoria')
            .isEmail().withMessage('Email non valida')
            .normalizeEmail()
    ];
};

const loginValidationRules = () => {
    return [
        body('username')
            .trim()
            .notEmpty().withMessage('Username è obbligatorio')
            .escape(), // Prevent XSS
        body('password')
            .notEmpty().withMessage('Password è obbligatoria')
    ];
};

const validate = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            error: errors.array()[0].msg,
            errors: errors.array() 
        });
    }
    next();
};

// Forgot username endpoint
app.post('/forgot-username', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email è obbligatoria.' });
    try {
        const snapshot = await db.collection('ristoranti').where('email', '==', email.toLowerCase()).limit(1).get();
        if (snapshot.empty) {
            return res.status(404).json({ success: false, error: 'Email non trovata nel sistema.' });
        }
        const restaurantDoc = snapshot.docs[0];
        const data = restaurantDoc.data();

        const subject = 'Recupero Username - Pannello Ristorante';
        const body = `Ciao,\n\nIl tuo username è: ${data.username}\n\nSe non hai richiesto tu questa operazione ignora la mail.`;

        if (mailer) {
            await mailer.sendMail({
                from: process.env.SMTP_FROM || process.env.SMTP_USER,
                to: email,
                subject,
                text: body
            });
        } else {
            console.log('[MAIL DISABLED] Body:', body);
        }

        res.json({ success: true, message: 'Username inviato via email.', usernameHint: data.username[0] });
    } catch (e) {
        console.error('Errore recupero username:', e);
        res.status(500).json({ error: 'Errore del server.' });
    }
});

// Forgot password endpoint (uses username to find email)
app.post('/forgot-password', async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Username è obbligatorio.' });
    try {
        const snapshot = await db.collection('ristoranti').where('username', '==', username).limit(1).get();
        if (snapshot.empty) return res.status(404).json({ success: false, error: 'Username non trovato.' });

        const restaurantDoc = snapshot.docs[0];
        const data = restaurantDoc.data();
        const resetToken = require('crypto').randomBytes(32).toString('hex');
        const resetExpires = new Date(Date.now() + 3600000); // 1 ora
        await restaurantDoc.ref.update({ resetToken, resetTokenExpires: resetExpires });

        const email = data.email;
        let maskedEmail = 'email non disponibile';
        if (email && email.includes('@')) {
            const [localPart, domain] = email.split('@');
            maskedEmail = localPart.slice(0,2) + '*'.repeat(Math.max(0, localPart.length-2)) + '@' + domain;
        }

        // Costruisci link dinamico basato su variabile di ambiente o fallback
        const baseFrontEnd = process.env.FRONTEND_BASE_URL || 'https://your-frontend-domain.com';
        const resetLink = `${baseFrontEnd.replace(/\/$/, '')}/reset-password.html?token=${resetToken}`;
        const subject = 'Reset Password - Pannello Ristorante';
        const body = `Ciao,\n\nHai richiesto un reset password.\nLink valido 1 ora:\n${resetLink}\n\nIn alternativa puoi copiare questo codice di reset e incollarlo nella pagina: \n${resetToken}\n\nSe non hai richiesto tu questa operazione ignora la mail.`;

        if (mailer) {
            await mailer.sendMail({
                from: process.env.SMTP_FROM || process.env.SMTP_USER,
                to: email,
                subject,
                text: body
            });
        } else {
            console.log('[MAIL DISABLED] Body:', body);
        }

        res.json({ success: true, message: 'Istruzioni inviate via email.', maskedEmail });
    } catch (error) {
        console.error('Error in forgot password:', error);
        res.status(500).json({ error: 'Errore interno del server.' });
    }
});

app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) {
        return res.status(400).json({ error: 'Token e nuova password sono obbligatori.' });
    }
    
    try {
        // Find restaurant with this reset token
        const snapshot = await db.collection('ristoranti')
            .where('resetToken', '==', token)
            .where('resetTokenExpires', '>', new Date())
            .limit(1)
            .get();
            
        if (snapshot.empty) {
            return res.status(400).json({ error: 'Token non valido o scaduto.' });
        }
        
        const restaurantDoc = snapshot.docs[0];
        
        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        // Update password and remove reset token
        await restaurantDoc.ref.update({
            passwordHash: hashedPassword,
            resetToken: admin.firestore.FieldValue.delete(),
            resetTokenExpires: admin.firestore.FieldValue.delete()
        });
        
        res.json({ success: true, message: 'Password reimpostata con successo.' });
        
    } catch (error) {
        console.error('Error in reset password:', error);
        res.status(500).json({ error: 'Errore interno del server.' });
    }
});

app.post('/login', authLimiter, loginValidationRules(), validate, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username e password sono obbligatori.' });
    try {
        const snapshot = await db.collection('ristoranti').where('username', '==', username).limit(1).get();
        if (snapshot.empty) return res.status(401).json({ success: false, error: 'Credenziali non valide.' });
        
        const restaurantDoc = snapshot.docs[0];
        const restaurantData = restaurantDoc.data();
        const isPasswordCorrect = await bcrypt.compare(password, restaurantData.passwordHash);

        if (!isPasswordCorrect) return res.status(401).json({ success: false, error: 'Credenziali non valide.' });

        res.json({ 
            success: true, 
            docId: restaurantDoc.id,
            restaurantId: restaurantData.restaurantId,
            nomeRistorante: restaurantData.nomeRistorante,
            logoUrl: restaurantData.logoUrl || null
        });
    } catch (error) {
        res.status(500).json({ error: 'Errore interno del server.' });
    }
});

app.post('/waiter-login-simple', authLimiter, loginValidationRules(), validate, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username e password sono obbligatori.' });
    }

    try {
        const restaurantsSnapshot = await db.collection('ristoranti').get();
        if (restaurantsSnapshot.empty) {
            return res.status(401).json({ error: 'Nessun ristorante trovato.' });
        }

        let foundWaiter = null;

        for (const doc of restaurantsSnapshot.docs) {
            const restaurantData = doc.data();
            const waiterCreds = restaurantData.settings?.waiterMode;

            if (waiterCreds && waiterCreds.enabled && waiterCreds.username === username) {
                const isPasswordCorrect = await bcrypt.compare(password, waiterCreds.passwordHash || '');
                if (isPasswordCorrect) {
                    foundWaiter = {
                        success: true,
                        docId: doc.id,
                        restaurantId: restaurantData.restaurantId,
                        nomeRistorante: restaurantData.nomeRistorante,
                        logoUrl: restaurantData.logoUrl || null
                    };
                    break; 
                }
            }
        }

        if (foundWaiter) {
            return res.json(foundWaiter);
        } else {
            return res.status(401).json({ success: false, error: 'Credenziali non valide.' });
        }

    } catch (error) {
        console.error("Errore nel login cameriere unificato:", error);
        res.status(500).json({ error: 'Errore del server durante il login del cameriere.' });
    }
});

app.post('/waiter-login', authLimiter, async (req, res) => {
    const { restaurantId, username, password } = req.body;
    if (!restaurantId || !username || !password) {
        return res.status(400).json({ error: 'ID Ristorante, username e password sono obbligatori.' });
    }

    try {
        const snapshot = await db.collection('ristoranti').where('restaurantId', '==', restaurantId).limit(1).get();
        
        if (snapshot.empty) {
            return res.status(404).json({ error: 'ID Ristorante non trovato o non valido.' });
        }
        
        const docSnap = snapshot.docs[0];
        const settings = docSnap.data().settings;
        
        if (!settings || !settings.waiterMode || !settings.waiterMode.enabled) {
            return res.status(403).json({ error: 'La modalità cameriere non è attiva per questo ristorante.' });
        }

        const waiterCreds = settings.waiterMode;
        if (username !== waiterCreds.username || !waiterCreds.passwordHash) {
            return res.status(401).json({ error: 'Credenziali non valide.' });
        }
        
        const isPasswordCorrect = await bcrypt.compare(password, waiterCreds.passwordHash);
        if (!isPasswordCorrect) {
            return res.status(401).json({ error: 'Credenziali non valide.' });
        }

        const data = docSnap.data();
        res.json({
            success: true,
            docId: docSnap.id,
            restaurantId: data.restaurantId,
            nomeRistorante: data.nomeRistorante,
            logoUrl: data.logoUrl || null
        });

    } catch (error) {
        res.status(500).json({ error: 'Errore del server.' });
    }
});

// --- ROTTE GESTIONE RISTORATORE (DASHBOARD) ---
app.post('/update-restaurant-details/:docId', upload.single('logo'), async (req, res) => {
    const { docId } = req.params;
    const { nomeRistorante } = req.body;
    try {
        const docRef = db.collection('ristoranti').doc(docId);
        const docSnap = await docRef.get();
        if (!docSnap.exists) return res.status(404).json({ error: 'Ristorante non trovato.' });

        const updateData = { nomeRistorante };
        if (req.file) {
            const oldData = docSnap.data();
            if (oldData.logoUrl && oldData.logoUrl.includes('cloudinary')) {
                const publicId = 'logos/' + oldData.logoUrl.split('/logos/')[1].split('.')[0];
                await cloudinary.uploader.destroy(publicId);
            }
            updateData.logoUrl = req.file.path;
        }
        await docRef.update(updateData);
        const finalData = (await docRef.get()).data();
        res.json({ success: true, message: 'Dati aggiornati!', nomeRistorante: finalData.nomeRistorante, logoUrl: finalData.logoUrl });
    } catch (error) {
        res.status(500).json({ error: 'Errore durante l\'aggiornamento.' });
    }
});

app.post('/update-waiter-credentials/:docId', async (req, res) => {
    const { docId } = req.params;
    const { username, password } = req.body;

    if (!username) return res.status(400).json({ error: 'Il nome utente è obbligatorio.' });

    try {
        const docRef = db.collection('ristoranti').doc(docId);
        const docSnap = await docRef.get();
        if (!docSnap.exists) return res.status(404).json({ error: 'Ristorante non trovato' });

        const settings = docSnap.data().settings || {};
        const waiterMode = settings.waiterMode || {};
        
        waiterMode.username = username;
        if (password) {
            const salt = await bcrypt.genSalt(10);
            waiterMode.passwordHash = await bcrypt.hash(password, salt);
        }

        await docRef.set({ settings: { ...settings, waiterMode } }, { merge: true });
        res.json({ success: true, message: 'Credenziali cameriere aggiornate!' });

    } catch (error) {
        res.status(500).json({ error: 'Errore durante l\'aggiornamento delle credenziali.' });
    }
});

// --- ROTTE SUPER ADMIN ---

// Toggle restaurant status (hide/show)
app.post('/toggle-restaurant-status/:restaurantId', async (req, res) => {
    const { restaurantId } = req.params;
    const { hide } = req.body;
    try {
        const restaurantDoc = db.collection('ristoranti').doc(restaurantId);
        const snap = await restaurantDoc.get();
        if (!snap.exists) return res.status(404).json({ error: 'Ristorante non trovato' });
        await restaurantDoc.update({ hidden: hide });
        res.json({ success:true, message: hide ? 'Ristorante disattivato' : 'Ristorante attivato' });
    } catch (e) {
        console.error('Errore toggle status:', e);
        res.status(500).json({ error: 'Errore durante aggiornamento stato' });
    }
});

// Update restaurant info
app.put('/restaurant/:restaurantId', upload.single('logo'), async (req, res) => {
    const { restaurantId } = req.params;
    const { nomeRistorante, username, email, password } = req.body;
    
    try {
        const restaurantDoc = db.collection('ristoranti').doc(restaurantId);
        const doc = await restaurantDoc.get();
        
        if (!doc.exists) {
            return res.status(404).json({ error: 'Ristorante non trovato' });
        }
        
        const updateData = {};
        
        // Update basic info
        if (nomeRistorante) updateData.nomeRistorante = nomeRistorante;
        if (username) updateData.username = username;
        if (email) updateData.email = email.toLowerCase();
        
        // Update password if provided
        if (password) {
            updateData.passwordHash = await bcrypt.hash(password, 10);
        }
        
        // Update logo if provided
        if (req.file && req.file.path) {
            updateData.logoUrl = req.file.path;
        }
        
        await restaurantDoc.update(updateData);
        
        res.json({ 
            success: true, 
            message: 'Ristorante aggiornato con successo' 
        });
    } catch (error) {
        console.error('Errore aggiornamento ristorante:', error);
        res.status(500).json({ error: 'Errore durante l\'aggiornamento del ristorante' });
    }
});

app.get('/restaurants', async (req, res) => {
    try {
        const snapshot = await db.collection('ristoranti').get();
    const restaurants = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json(restaurants);
    } catch (error) {
        res.status(500).json({ error: 'Impossibile recuperare i ristoranti.' });
    }
});

app.post('/create-restaurant', upload.single('logo'), restaurantValidationRules(), validate, async (req, res) => {
    const { nomeRistorante, username, password, email } = req.body;
    if (!nomeRistorante || !username || !password || !email) {
        return res.status(400).json({ error: 'Tutti i campi sono obbligatori (nome, username, password, email).' });
    }
    
    try {
        // Check if email already exists
        const emailCheck = await db.collection('ristoranti').where('email', '==', email.toLowerCase()).get();
        if (!emailCheck.empty) {
            return res.status(400).json({ error: 'Email già registrata nel sistema.' });
        }
        
        // Check if username already exists
        const usernameCheck = await db.collection('ristoranti').where('username', '==', username).get();
        if (!usernameCheck.empty) {
            return res.status(400).json({ error: 'Username già in uso.' });
        }
        
        const salt = bcrypt.genSaltSync(10);
        const passwordHash = bcrypt.hashSync(password, salt);
        const restaurantId = nomeRistorante.toLowerCase().replace(/\s+/g, '-') + '-' + Date.now().toString().slice(-5);
        
        const defaultWaiterPassword = '1234';
        const waiterPasswordHash = bcrypt.hashSync(defaultWaiterPassword, salt);

        const defaultSettings = {
            ayce: { enabled: false, price: 25.00, limitOrders: false, maxOrders: 3 },
            coperto: { enabled: false, price: 2.00 },
            waiterMode: { enabled: false, username: 'cameriere', passwordHash: waiterPasswordHash },
            reservations: { 
                enabled: true, 
                startTime: '11:00', 
                endTime: '23:00', 
                slotDuration: 120 
            }
        };

        const newRestaurant = {
            nomeRistorante, 
            username, 
            passwordHash,
            email: email.toLowerCase(),
            restaurantId,
            logoUrl: req.file ? req.file.path : null,
            settings: defaultSettings,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };

        await db.collection('ristoranti').add(newRestaurant);
        res.status(201).json({ success: true, message: 'Ristorante creato con successo.' });
    } catch (error) {
        res.status(500).json({ error: 'Errore nella creazione del ristorante.' });
    }
});

app.delete('/delete-restaurant/:docId', async (req, res) => {
    const { docId } = req.params;
    try {
        const docRef = db.collection('ristoranti').doc(docId);
        const docSnap = await docRef.get();
        if (!docSnap.exists) return res.status(404).json({ error: 'Ristorante non trovato.' });

        const collections = await docRef.listCollections();
        for (const collection of collections) {
            await deleteCollection(collection);
        }

        await docRef.delete();

        res.json({ success: true, message: 'Ristorante e tutti i dati associati eliminati con successo.' });
    } catch (error) {
        res.status(500).json({ error: 'Errore durante l\'eliminazione del ristorante.' });
    }
});

app.post('/update-restaurant-admin/:docId', upload.single('logo'), async (req, res) => {
    const { docId } = req.params;
    const { nomeRistorante, username, password } = req.body;
    
    try {
        const docRef = db.collection('ristoranti').doc(docId);
        const docSnap = await docRef.get();
        if (!docSnap.exists) return res.status(404).json({ error: 'Ristorante non trovato.' });

        const updateData = { nomeRistorante, username };
        if (password) {
            const salt = bcrypt.genSaltSync(10);
            updateData.passwordHash = bcrypt.hashSync(password, salt);
        }
        if (req.file) {
            const oldData = docSnap.data();
            if (oldData.logoUrl && oldData.logoUrl.includes('cloudinary')) {
                const publicId = 'logos/' + oldData.logoUrl.split('/logos/')[1].split('.')[0];
                await cloudinary.uploader.destroy(publicId);
            }
            updateData.logoUrl = req.file.path;
        }

        await docRef.update(updateData);
        res.json({ success: true, message: 'Dati aggiornati!' });
    } catch (error) {
        res.status(500).json({ error: 'Errore durante l\'aggiornamento.' });
    }
});

// --- ROTTE STATISTICHE E UTILITY ---
app.get('/global-stats', async (req, res) => {
    try {
        const { startDate, endDate } = req.query;
        if (!startDate || !endDate) {
            return res.status(400).json({ error: 'Le date di inizio e fine sono richieste.' });
        }

        const start = new Date(startDate);
        const end = new Date(endDate);
        end.setHours(23, 59, 59, 999);

        const restaurantsSnapshot = await db.collection('ristoranti').get();
        const restaurants = restaurantsSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

        const allStats = [];

        for (const restaurant of restaurants) {
            const sessionsSnapshot = await db.collection(`ristoranti/${restaurant.id}/historicSessions`).get();

            let totalRevenue = 0, sessionCount = 0, dishesSold = 0;

            sessionsSnapshot.forEach(doc => {
                const sessionData = doc.data();
                if (!sessionData.paidAt || typeof sessionData.paidAt.toDate !== 'function') return;
                
                const paidAtDate = sessionData.paidAt.toDate();
                if (paidAtDate < start || paidAtDate > end) return;

                sessionCount++;
                totalRevenue += sessionData.totalAmount || 0;
                (sessionData.orders || []).forEach(item => {
                    dishesSold += item.quantity || 0;
                });
            });

            allStats.push({
                id: restaurant.id, // necessario per aprire analitiche specifiche nel pannello admin
                name: restaurant.nomeRistorante,
                totalRevenue, sessionCount, dishesSold
            });
        }

        res.json(allStats);

    } catch (error) {
        res.status(500).json({ error: 'Impossibile calcolare le statistiche globali.' });
    }
});

/**
 * Analytics endpoint consumed by dashboard.html
 * GET /analytics/:docId?startDate=ISO&endDate=ISO
 * Returns:
 * {
 *   totalRevenue, totalSessions,
 *   dailyRevenue: [{date:'YYYY-MM-DD', revenue:Number}],
 *   dailySessions: [{date:'YYYY-MM-DD', sessions:Number}],
 *   topDishes: [{name, quantity}]
 * }
 */
app.get('/analytics/:docId', async (req, res) => {
    const { docId } = req.params;
    const { startDate, endDate } = req.query;

    let start, end;
    try {
        if (startDate && endDate) {
            start = new Date(startDate);
            end = new Date(endDate);
        } else {
            // Default: last 7 days
            end = new Date();
            start = new Date();
            start.setDate(end.getDate() - 6);
        }
        if (isNaN(start.getTime()) || isNaN(end.getTime())) {
            return res.status(400).json({ error: 'Parametri data non validi.' });
        }
        // Normalize boundaries
        start.setHours(0,0,0,0);
        end.setHours(23,59,59,999);
    } catch (e) {
        return res.status(400).json({ error: 'Formattazione date non valida.' });
    }

    try {
        // Verify restaurant doc exists (optional but defensive)
        const restoRef = db.collection('ristoranti').doc(docId);
        const restoSnap = await restoRef.get();
        if (!restoSnap.exists) {
            return res.status(404).json({ error: 'Ristorante non trovato.' });
        }

        const sessionsRef = db.collection(`ristoranti/${docId}/historicSessions`)
            .where('paidAt', '>=', admin.firestore.Timestamp.fromDate(start))
            .where('paidAt', '<=', admin.firestore.Timestamp.fromDate(end));

        const snap = await sessionsRef.get();

        let totalRevenue = 0;
        let totalSessions = 0;

        const dayRevenueMap = new Map();   // dateStr -> revenue
        const daySessionsMap = new Map();  // dateStr -> count
        const dishesMap = new Map();       // dishName -> quantity

        snap.forEach(docSnap => {
            const data = docSnap.data() || {};
            const paidAtTs = data.paidAt;
            if (!paidAtTs) return;

            const paidAtDate = paidAtTs.toDate();
            const dateStr = paidAtDate.toISOString().slice(0,10);

            const sessionRevenue = Number(data.totalAmount) || 0;
            totalRevenue += sessionRevenue;
            totalSessions += 1;

            dayRevenueMap.set(dateStr, (dayRevenueMap.get(dateStr) || 0) + sessionRevenue);
            daySessionsMap.set(dateStr, (daySessionsMap.get(dateStr) || 0) + 1);

            const orders = Array.isArray(data.orders) ? data.orders : [];
            orders.forEach(item => {
                if (!item || !item.name) return;
                const qty = Number(item.quantity) || 1;
                dishesMap.set(item.name, (dishesMap.get(item.name) || 0) + qty);
            });
        });

        // Build continuous date range for daily arrays
        const dailyRevenue = [];
        const dailySessions = [];
        for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
            const dateStr = d.toISOString().slice(0,10);
            dailyRevenue.push({
                date: dateStr,
                revenue: Number((dayRevenueMap.get(dateStr) || 0).toFixed(2))
            });
            dailySessions.push({
                date: dateStr,
                sessions: daySessionsMap.get(dateStr) || 0
            });
        }

        // Top dishes (sorted desc by quantity)
        const topDishes = Array.from(dishesMap.entries())
            .map(([name, quantity]) => ({ name, quantity }))
            .sort((a,b) => b.quantity - a.quantity)
            .slice(0, 50); // cap for safety

        return res.json({
            success: true,
            totalRevenue: Number(totalRevenue.toFixed(2)),
            totalSessions,
            dailyRevenue,
            dailySessions,
            topDishes
        });
    } catch (error) {
        console.error('Analytics error:', error);
        return res.status(500).json({ error: 'Errore nel recupero delle analitiche.' });
    }
});


app.get('/cloudinary-usage', async (req, res) => {
    try {
        const usage = await cloudinary.api.usage({ credits: true });
        res.status(200).json(usage);
    } catch (error) {
        res.status(500).json({ error: "Impossibile recuperare i dati di utilizzo." });
    }
});

app.get('/', (req, res) => {
  res.send('Backend per Ristoranti Attivo e Corretto!');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server attivo su http://localhost:${PORT}`));

// --- NUOVE ROTTE UNIFICATE ---
app.post('/unified-login', authLimiter, loginValidationRules(), validate, async (req, res) => {
    const { username, password } = req.body;
    try {
        // 1. Tentativo CAMERIERE (scan ristoranti)
        const restaurantsSnapshot = await db.collection('ristoranti').get();
        for (const docSnap of restaurantsSnapshot.docs) {
            const data = docSnap.data();
            const waiter = data.settings?.waiterMode;
            if (waiter?.enabled && waiter.username === username) {
                if (waiter.passwordHash && await bcrypt.compare(password, waiter.passwordHash)) {
                    return res.json({
                        success: true,
                        userType: 'waiter',
                        docId: docSnap.id,
                        restaurantId: data.restaurantId,
                        nomeRistorante: data.nomeRistorante,
                        logoUrl: data.logoUrl || null
                    });
                } else {
                    // username match ma password sbagliata → interrompo senza provare owner (comportamento coerente)
                    return res.status(401).json({ success:false, error:'Credenziali non valide.' });
                }
            }
        }

        // 2. Tentativo RISTORATORE (match diretto su username)
        const ownerSnapshot = await db.collection('ristoranti').where('username', '==', username).limit(1).get();
        if (!ownerSnapshot.empty) {
            const docSnap = ownerSnapshot.docs[0];
            const data = docSnap.data();
            const ok = await bcrypt.compare(password, data.passwordHash || '');
            if (ok) {
                return res.json({
                    success: true,
                    userType: 'owner',
                    docId: docSnap.id,
                    restaurantId: data.restaurantId,
                    nomeRistorante: data.nomeRistorante,
                    logoUrl: data.logoUrl || null
                });
            }
            return res.status(401).json({ success:false, error:'Credenziali non valide.' });
        }

        return res.status(401).json({ success:false, error:'Credenziali non valide.' });
    } catch (error) {
        console.error('Unified login error:', error);
        res.status(500).json({ error: 'Errore interno del server.' });
    }
});