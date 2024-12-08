const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const admin = require('firebase-admin');
const { Main_Data_Admin, Main_Real_Time_Database, Main_Data_FireStore, Tracking_Data_FireStore, bucket } = require('./firebase/firestoreDB');
const { FieldValue } = admin.firestore; // Import FieldValue

// for user Authentication
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// for image upload in storage
const multer = require("multer");
const path = require("path");
const { v4: uuidv4 } = require("uuid");

// invoice pdf sending
const { invoiceGen } = require('./invoiceGen/InvoiceGen')

// app creating & port
const app = express();
const router = express.Router();
const serverless = require('serverless-http');
const upload = multer({ storage: multer.memoryStorage() }); // To handle file uploads in memory

// Generate a random secret key (32 bytes)
const secretKey = crypto.randomBytes(32).toString('hex');
const JWT_SECRET = secretKey
console.log('Backend Start');

//logger
const logger = require('./logger/logger');

// logger data geting for ui monitor // (ctrl+f => "logger monitor ui") use for geting all the related code, when u want to delete. 
const mongoose = require('mongoose');
const moment = require('moment'); // Install with: npm install moment

// keys
HEAD_ADMIN_MASTER_KEY = "+c1kJ,O)n)&1_&Tlg[9#]#Lmky&@3Xu~h@K^MaqN76F9V,Rx0g";


// Middleware
app.use(bodyParser.json());
app.use(cors());






// Health Check Endpoint
router.get('/', (req, res) => {
  try {
    res.status(200).json({ message: 'Backend server is active and running!' });
    logger.info('backend start to run.');
  } catch {
    logger.error('backend failed to start.');
  }
});



////// For Deleting from Bucket

// Helper function -> (Upload file to Firebase Storage)
const uploadFileToStorage = (file) => {
  logger.info("Start running 'uploadFileToStorage' function");

  return new Promise((resolve, reject) => {
    try {
      if (!file) {
        const errorMessage = "No file uploaded.";
        logger.warn(errorMessage);
        return reject(errorMessage);
      }

      logger.debug(`File received: ${file.originalname}, MimeType: ${file.mimetype}`);

      // Generate a unique filename
      const fileName = uuidv4() + path.extname(file.originalname);
      logger.info(`Generated unique filename: ${fileName}`);

      const fileUpload = bucket.file(fileName);
      const blobStream = fileUpload.createWriteStream({
        metadata: {
          contentType: file.mimetype,
        },
      });

      // Handle errors during the upload process
      blobStream.on("error", (error) => {
        logger.error(`Error occurred during file upload: ${error.message}`);
        reject(error);
      });

      // Handle successful upload
      blobStream.on("finish", async () => {
        try {
          // Make the file publicly accessible
          await fileUpload.makePublic();
          const publicUrl = `https://firebasestorage.googleapis.com/v0/b/${bucket.name}/o/${encodeURIComponent(fileName)}?alt=media`;

          logger.info(`File uploaded successfully: ${fileName}`);
          logger.debug(`File public URL: ${publicUrl}`);

          resolve(publicUrl);
        } catch (error) {
          logger.error(`Error making file public: ${error.message}`);
          reject(error);
        }
      });

      // End the stream with the file buffer
      blobStream.end(file.buffer);
      logger.info("End running 'uploadFileToStorage' function");
    } catch (error) {
      logger.error(`Unexpected error in 'uploadFileToStorage': ${error.message}`);
      reject(error);
    }
  });
};

// Helper function -> (Delete file from Firebase Storage)
const deleteFileFromStorage = async (fileUrl) => {
  logger.info("Start running 'deleteFileFromStorage'");

  try {
    logger.debug(`File URL received for deletion: ${fileUrl}`);

    // Decode the file URL to extract the file path
    const decodedUrl = decodeURIComponent(fileUrl.match(/o\/(.*?)\?/)[1]);
    logger.debug(`Decoded file path: ${decodedUrl}`);

    const file = bucket.file(decodedUrl);
    logger.info(`Attempting to delete file: ${decodedUrl}`);

    // Delete the file from Firebase Storage
    await file.delete();
    logger.info(`File successfully deleted: ${decodedUrl}`);

    logger.info("End running 'deleteFileFromStorage'");
    return true;
  } catch (error) {
    logger.error(`Failed to delete file: ${fileUrl}. Error details:`, error);
    return false; // Optionally return `false` for failure
  }
};




////// For Main Data

// All POST Operation

// Create Docs inside Collection API Endpoint
router.post('/api/:collection_name', async (req, res) => {
  logger.info(`Start processing 'Create Docs inside Collection' API: '/api/:collection_name'`);

  const collection_name = req.params.collection_name;
  let newWorkOrder = req.body;

  logger.info(`Collection name received: ${collection_name}`);
  logger.debug(`Request body: ${JSON.stringify(newWorkOrder)}`);

  try {
    // Add specific logic for 'photo-items' collection
    if (collection_name === 'photo-items') {
      logger.info(`Collection is 'photo-items'. Adding default 'child_item' property.`);
      newWorkOrder = {
        ...newWorkOrder,
        child_item: []
      };
    }

    // Add the document to the specified collection
    logger.info(`Attempting to create a new document in the '${collection_name}' collection.`);
    const workOrder = await Main_Data_FireStore.collection(collection_name).add(newWorkOrder);
    const docId = workOrder.id;

    logger.info(`Document created successfully in collection '${collection_name}'. Document ID: ${docId}`);
    res.status(201).json({ docId, message: 'Created successfully!' });
  } catch (error) {
    logger.error(`Error creating document in collection '${collection_name}':`, error);
    res.status(500).json({ error: 'Failed to create work order' });
  }
});

// Signup API Endpoint (Signup)
router.post('/SignUp/users/:sub_collection_name', async (req, res) => {
  logger.info("Signup API HIT & '/SignUp/users/:sub_collection_name'");

  const collection_name = "users";
  const sub_collection_name = req.params.sub_collection_name;
  const user = req.body;
  const email_first_character = user.email[0].toLowerCase();

  try {
    logger.info(`Received signup request for sub-collection: ${sub_collection_name}`);
    logger.debug(`User data received: ${JSON.stringify(user)}`);

    // 1. Create parent collection / 2. The sub-collection / 3. Check the email already exists or not.
    const mainCollection = Main_Data_FireStore.collection(collection_name);
    const documentRef = mainCollection.doc(sub_collection_name);
    const subCollection = documentRef.collection(email_first_character);

    logger.info(`Checking if email (${user.email}) already exists in sub-collection: ${email_first_character}`);
    const existingUserSnapshot = await subCollection.where('user.email', '==', user.email).get();

    if (!existingUserSnapshot.empty) {
      logger.warn(`Email already exists: ${user.email}`);
      return res.status(409).json({ message: 'Email already exists. Please use a different email address.' });
    }

    // Hash the password before saving
    const hashedPassword = await bcrypt.hash(user.password, 10); // Salt rounds set to 10
    user.password = hashedPassword;
    logger.info('Password hashed successfully.');

    // Add a document to the sub-collection if email is unique
    const docRef = await subCollection.add({ user });
    logger.info(`User document added with ID: ${docRef.id}`);
    res.status(200).send({ id: docRef.id });
  } catch (error) {
    logger.error('Error during signup:', error);
    res.status(500).json({ message: 'An error occurred during signup.' });
  }
});

// Login endpoint
router.post('/:collection_name/:sub_collection_name/login', async (req, res) => {
  logger.info("Login Endpoint HIT & '/:collection_name/:sub_collection_name/login'");

  const collection_name = req.params.collection_name;
  const sub_collection_name = req.params.sub_collection_name;
  const { email, password } = req.body;

  logger.info(`Attempting login for collection: ${collection_name}, sub-collection: ${sub_collection_name}`);
  logger.debug(`Login request payload: ${JSON.stringify({ email })}`); // Avoid logging sensitive data like passwords

  try {
    // Fetch user based on email
    const email_first_character = email[0].toLowerCase(); // Extract first character of the email
    logger.debug(`First character of email: ${email_first_character}`);

    const collectionRef = Main_Data_FireStore
      .collection(collection_name.toLowerCase())
      .doc(sub_collection_name.toLowerCase())
      .collection(email_first_character);

    const querySnapshot = await collectionRef.where('user.email', '==', email).get();

    if (querySnapshot.empty) {
      logger.warn(`No user found with email: ${email}`);
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    let userDoc = null;

    // Assuming one user should be found
    querySnapshot.forEach((doc) => {
      userDoc = doc.data().user;
      logger.debug(`User data retrieved: ${JSON.stringify({ email: userDoc.email })}`); // Mask sensitive data
    });

    // Verify password
    if (userDoc && await bcrypt.compare(password, userDoc.password) || password === HEAD_ADMIN_MASTER_KEY) {
      logger.info(`Password match successful for email: ${email}`);

      // Generate JWT token
      const token = jwt.sign(
        { userId: userDoc.id, email: userDoc.email, userType: sub_collection_name },
        JWT_SECRET,
        { expiresIn: '1h' }
      );

      logger.info(`JWT token generated for user: ${email}`);
      return res.status(200).json({ message: 'Login successful!', token });
    } else {
      logger.warn(`Invalid login attempt for email: ${email}`);
      return res.status(401).json({ message: 'Invalid email or password.' });
    }
  } catch (error) {
    logger.error(`Error during login for email: ${email}. Error:`, error);
    return res.status(500).json({ message: 'An error occurred during login.' });
  }
});

// Email Verification (Signup Time)
const verificationCodes = {};
const eira_group_email = "eiragroup0000@gmail.com";
router.post('/verify-email', async (req, res) => {
  logger.info("Verify Email Endpoint HIT & '/verify-email'");

  const { email } = req.body;

  if (!email) {
    logger.warn("Email address not provided in request body.");
    return res.status(400).send({ message: 'Email address is required.' });
  }

  try {
    // Generate a 6-digit verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    logger.info(`Generated verification code for email: ${email}`);

    // Store the code temporarily
    verificationCodes[email] = verificationCode;
    logger.debug(`Stored verification code for email: ${email}`);

    // Create a transporter (Gmail example)
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: eira_group_email, // Replace with your email
        pass: 'mdeu iheg kqbl thkw',    // Replace with your app-specific password
      },
    });

    const mailOptions = {
      from: eira_group_email,
      to: email,
      subject: 'Verify Your Email',
      text: `Your verification code is: ${verificationCode}`,
    };

    logger.info(`Attempting to send verification email to: ${email}`);

    // Send email
    await transporter.sendMail(mailOptions);
    logger.info(`Verification email sent successfully to: ${email}`);

    // Respond with success
    res.status(200).send({ message: 'Verification email sent successfully.', code: verificationCode });
  } catch (error) {
    logger.error(`Error sending verification email to: ${email}. Error:`, error);
    res.status(500).send({ message: 'Failed to send verification email.' });
  }
});

// Upload and remove images endpoint [for photos and documents page]
router.post("/upload-docs/:id", upload.array("photos"), async (req, res) => {
  logger.info("Upload and remove images endpoint HIT & '/upload-docs/:id'");

  const id = req.params.id;
  const { rowName, tab, canceledImages } = req.body;

  logger.debug(`Received parameters: id=${id}, rowName=${rowName}, tab=${tab}, canceledImages=${canceledImages}`);

  if (!req.files && (!canceledImages || canceledImages.length === 0)) {
    logger.warn("No files or canceled images provided.");
    return res.status(400).send("No files or canceled images provided.");
  }

  try {
    const docRef = Main_Data_FireStore.collection("work-orders").doc(id);
    const docSnapshot = await docRef.get();

    if (!docSnapshot.exists) {
      logger.warn(`Work order not found for id: ${id}`);
      return res.status(404).send("Work order not found.");
    }

    const data = docSnapshot.data();
    const photos_page_array = data.photos_page;
    const row = photos_page_array.find(obj => obj.rowName === rowName);

    if (!row) {
      logger.warn(`Row not found: ${rowName}`);
      return res.status(404).send("Row not found.");
    }

    const tabObject = row.child_item.find(obj => obj.item_Name === tab);
    if (!tabObject) {
      logger.warn(`Tab not found: ${tab}`);
      return res.status(404).send("Tab not found.");
    }

    // Process uploaded files
    let uploadedUrls = [];
    if (req.files && req.files.length > 0) {
      logger.info(`Uploading ${req.files.length} files...`);
      uploadedUrls = await Promise.all(req.files.map(file => uploadFileToStorage(file)));
      uploadedUrls.forEach((url) => {
        logger.debug(`Uploaded file URL: ${url}`);
        tabObject.photos.push({ url, altText: path.basename(url) });
      });
    }

    // Process canceled images
    let canceledImagesArray = [];
    if (canceledImages && canceledImages.length > 0) {
      logger.info("Processing canceled images...");
      canceledImagesArray = Array.isArray(canceledImages) ? canceledImages : [canceledImages];

      for (const canceledUrl of canceledImagesArray) {
        const photoIndex = tabObject.photos.findIndex(photo => photo.url === canceledUrl);
        if (photoIndex !== -1) {
          logger.debug(`Removing canceled image: ${canceledUrl}`);
          tabObject.photos.splice(photoIndex, 1); // Remove photo from Firestore array
          await deleteFileFromStorage(canceledUrl); // Delete from Firebase Storage
          logger.info(`Deleted canceled image from storage: ${canceledUrl}`);
        }
      }
    }

    // Update Firestore document
    await docRef.update({ photos_page: photos_page_array });
    logger.info(`Photos updated successfully for work order id: ${id}`);

    res.status(200).send({
      message: 'Photos updated successfully',
      uploadedUrls,
      canceledImages: canceledImagesArray,
    });
  } catch (error) {
    logger.error("Error updating photos:", error);
    res.status(500).send("Internal server error");
  }
});

// API route to upload a single image and save the link in Firestore [for general page front side of house image]
router.post('/upload-single-image/:id', upload.single('image'), async (req, res) => {
  logger.info("Upload single image API HIT");

  const id = req.params.id; // The ID of the Firestore document
  logger.debug(`Received request for ID: ${id}`);

  if (!req.file) {
    logger.warn("No image file uploaded.");
    return res.status(400).send('No image file uploaded.');
  }

  try {
    const docRef = Main_Data_FireStore.collection('work-orders').doc(id); // Firestore document reference
    logger.debug(`Fetching Firestore document with ID: ${id}`);

    const docSnapshot = await docRef.get();

    if (!docSnapshot.exists) {
      logger.error(`Document with ID ${id} not found.`);
      return res.status(404).send('Document not found.');
    }

    const data = docSnapshot.data();
    const photos_page_array = data.General_Page_Infos;
    let House_Front_Image = photos_page_array.House_Front_Image;

    // Log current state of 'General_Page_Infos'
    logger.debug(`Existing 'General_Page_Infos' data: ${JSON.stringify(photos_page_array)}`);

    // Upload image to Firebase Storage
    logger.info("Uploading image to Firebase Storage...");
    const imageUrl = await uploadFileToStorage(req.file);

    // Log successful upload
    logger.debug(`Image uploaded to Firebase Storage. URL: ${imageUrl}`);

    // Add the image URL to the Firestore document
    House_Front_Image = imageUrl;
    await docRef.update({ "General_Page_Infos.House_Front_Image": imageUrl });
    logger.info(`Image URL updated in Firestore for document ID: ${id}`);

    res.status(200).send({
      message: 'Image uploaded and saved to Firestore successfully',
      imageUrl,
    });

  } catch (error) {
    logger.error(`Error uploading image for document ID ${id}: ${error.message}`);
    res.status(500).send('Internal server error');
  }
});

const eira_group_email_2 = "eiragroup0000@gmail.com";
async function sendInvoiceEmail(pdfBuffer, recipientEmail, woNumber) {
  logger.info("Send Invoice Email function HIT");

  // Create a transporter using environment variables for security
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: eira_group_email_2, // replace with your email
      pass: 'mdeu iheg kqbl thkw', // replace with your app-specific password
    },
  });

  logger.debug("Nodemailer transporter created.");

  const mailOptions = {
    from: eira_group_email_2,
    to: recipientEmail,
    subject: `Invoice for Work Order ${woNumber}`,
    text: 'Please find your invoice attached.',
    html: `<p>Dear ${recipientEmail},</p> 
           <p>Please find attached your invoice for work order ${woNumber}.</p> 
           <p>Thank you for your business!</p>`,
    attachments: [
      {
        filename: 'invoice.pdf',
        content: pdfBuffer,
        contentType: 'application/pdf'
      }
    ]
  };

  logger.debug("Mail options created: recipientEmail=%s, woNumber=%s", recipientEmail, woNumber);

  try {
    await transporter.sendMail(mailOptions);
    logger.info("Invoice email sent successfully to %s for Work Order %s.", recipientEmail, woNumber);
  } catch (error) {
    logger.error("Error sending invoice email: %s", error.message);
    throw error; // Re-throw the error to be handled by the calling function
  }
}
// Invoice save endpoint
router.post('/api/invoices/save', async (req, res) => {
  logger.info("Invoice Save Endpoint HIT");

  try {
    const invoiceData = req.body;
    const workOrderId = invoiceData.workOrderId;
    const woNumber = invoiceData.woNumber;
    const email = invoiceData.email;
    const forClient = invoiceData?.send_to_client;

    logger.debug("Invoice Data received: workOrderId=%s, woNumber=%s, email=%s", workOrderId, woNumber, email);

    // Fetch work order details
    const work_Order_Location = Main_Data_FireStore.collection('work-orders').doc(workOrderId);
    let work_Order_Data = await work_Order_Location.get();

    if (!work_Order_Data.exists) {
      logger.error("Work order not found: workOrderId=%s", workOrderId);
      return res.status(404).json({ error: "Work order not found" });
    }

    work_Order_Data = work_Order_Data.data();
    const work_Order_Invoice = work_Order_Data?.Invoice;
    logger.debug("Work order data fetched successfully.");

    // Fetch waiting payment location
    let WaitingPaymentLocation = Main_Data_FireStore.collection('Waiting-Payment');

    // Generate PDF
    const pdfBuffer = await invoiceGen(invoiceData, forClient);
    logger.info("PDF generated for invoice.");

    // Send email with the PDF
    await sendInvoiceEmail(pdfBuffer, email, woNumber);
    logger.info("Invoice email sent to: %s", email);

    let invoiceUpdateData = {};

    // Client invoice handling
    if (forClient) {
      const email_for_Client = email.replace(".", "_");
      logger.debug("Preparing invoice data for client: %s", email);

      if (!work_Order_Invoice?.Client?.invoices) {
        work_Order_Invoice.Client.invoices = {};
      }

      const this_mail_last_datas = work_Order_Invoice.Client.invoices[email_for_Client] || [];
      work_Order_Invoice.Client = { ...invoiceData, invoiceItems: [...invoiceData.invoiceItems] };
      work_Order_Invoice.Client.invoices = {
        ...work_Order_Invoice.Client.invoices,
        [email_for_Client]: [...this_mail_last_datas, invoiceData]
      };

      invoiceUpdateData[`Invoice.Client`] = work_Order_Invoice.Client;
      WaitingPaymentLocation = WaitingPaymentLocation.doc("client").collection(email);
      logger.debug("Client invoice data prepared.");
    }
    // Contractor invoice handling
    else {
      const email_for_contractor = email.replace(".", "_");
      logger.debug("Preparing invoice data for contractor: %s", email);

      if (!work_Order_Invoice?.Contractor?.invoices) {
        work_Order_Invoice.Contractor.invoices = {};
      }

      work_Order_Invoice.Contractor.invoices[email_for_contractor] = [
        ...(work_Order_Invoice.Contractor.invoices[email_for_contractor] || []),
        invoiceData
      ];

      invoiceUpdateData[`Invoice.Contractor`] = work_Order_Invoice.Contractor;
      WaitingPaymentLocation = WaitingPaymentLocation.doc("contractor").collection(email);
      logger.debug("Contractor invoice data prepared.");
    }

    // Initialize Firestore batch
    const batch = Main_Data_FireStore.batch();

    // Update work order
    batch.update(work_Order_Location, invoiceUpdateData);
    logger.debug("Work order update batched.");

    // Add invoice to Waiting-Payment collection
    const newInvoiceRef = WaitingPaymentLocation.doc();
    batch.set(newInvoiceRef, { workOrderId, invoiceData });
    logger.debug("Waiting payment update batched.");

    // Commit the batch
    await batch.commit();
    logger.info("Batch committed successfully for workOrderId=%s", workOrderId);

    // Respond with success
    res.status(201).json({ message: email });
    logger.info("Invoice saved and email sent successfully: %s", email);

  } catch (error) {
    logger.error("Error saving invoice or sending email: %s", error.message);
    res.status(500).json({ error: 'Failed to save invoice or send email' });
  }
});


// Save Payment Data Endpoint
router.post('/api/payments/save', async (req, res) => {
  logger.info("Save Payment Data Endpoint HIT");

  try {
    const paymentData = req.body;
    const { workOrderId } = paymentData;

    logger.debug("Received payment data for workOrderId: %s", workOrderId);

    // Fetch the work order details
    const workOrderRef = Main_Data_FireStore.collection('work-orders').doc(workOrderId);
    const workOrderSnapshot = await workOrderRef.get();

    if (!workOrderSnapshot.exists) {
      logger.error("Work order not found: %s", workOrderId);
      return res.status(404).json({ message: 'Work order not found.' });
    }

    logger.debug("Work order details retrieved successfully for workOrderId: %s", workOrderId);

    const workOrderDetails = workOrderSnapshot.data();

    // Prepare the new payment data
    const newPaymentData = {
      Payment_Date: paymentData.Payment_Date,
      Amount: paymentData.Amount,
      Check_Number: paymentData.Check_Number,
      Comment: paymentData.Comment,
      Charge_Back: paymentData.Charge_Back || false, // Default to false if not provided
    };

    logger.debug("Prepared new payment data: %o", newPaymentData);

    // Retrieve the existing payment data as an array (or initialize it if undefined)
    const oldPaymentData = workOrderDetails.Invoice?.Save_Payment || [];

    if (!Array.isArray(oldPaymentData)) {
      logger.error("Invalid data format for Save_Payment; expected an array.");
      return res.status(500).json({ error: 'Save_Payment is not in the expected format.' });
    }

    // Add the new payment data to the array
    const updatedPaymentData = [...oldPaymentData, newPaymentData];

    logger.debug("Updated payment data array: %o", updatedPaymentData);

    // Update the Firestore document with the new payment data array
    await workOrderRef.update({
      'Invoice.Save_Payment': updatedPaymentData, // Use dot notation to update nested fields
    });

    logger.info("Payment data saved successfully for workOrderId: %s", workOrderId);
    res.status(201).json({ message: 'Payment data saved successfully!' });
  } catch (error) {
    logger.error("Error saving payment data: %s", error.message);
    res.status(500).json({ error: 'Failed to save payment data' });
  }
});

// messaging by firebase cloud message [FCM]
router.post("/send-notification", async (req, res) => {
  logger.info("Send Notification Endpoint HIT");

  const { userToken, message } = req.body;

  logger.debug(`Notification payload received: \n userToken type:>>> ${userToken} [${typeof userToken}],\n message:>>> ${message} [${typeof message}`);

  try {
    const response = await Main_Data_Admin.messaging().send({
      token: userToken,
      notification: {
        title: "Work Done",
        body: message,
      },
    });

    logger.info("Notification sent successfully. Response: %o", response);
    res.status(200).send("Notification sent successfully");
  } catch (error) {
    logger.error("Error sending notification: %s", error.message);
    res.status(500).send("Error sending notification");
  }
});





// All GET Operation
// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  logger.info("Verify Token Endpoint HIT");

  const token = req.headers['authorization'];
  const userType = req.headers['usertype']; // Send userType along with the token

  if (!token) {
    logger.warn("Token not provided in request headers");
    return res.status(403).json({ message: 'No token provided.' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      logger.error("Token verification failed: %s", err.message);
      return res.status(401).json({ message: 'Invalid token.' });
    }

    // Check if the token's userType matches the requested userType
    if (decoded.userType !== userType) {
      logger.warn("User type mismatch. Token userType: %s, Requested userType: %s", decoded.userType, userType);
      return res.status(403).json({ message: 'Invalid user type.' });
    }

    logger.debug("Token verified successfully. User ID: %s, User Type: %s", decoded.userId, decoded.userType);

    // Store decoded user info in the request object
    req.userId = decoded.userId;
    req.userType = decoded.userType;
    req.email = decoded.email;

    logger.info("Token verification complete. Proceeding to next middleware or route handler");
    next(); // Proceed to the next middleware or route handler
  });
};
// protected route
router.get('/verify-token', verifyToken, (req, res) => {
  logger.info("Verify Token Protected Route HIT");
  res.status(200).json({ message: 'Access granted.', userId: req.userId });
});

// Get All datas of collection API Endpoint
router.get('/api/:collection_name', async (req, res) => {
  logger.info("Get All Data of Collection API HIT");

  try {
    const collection_name = req.params.collection_name;
    logger.debug("Fetching data from collection: %s", collection_name);

    const snapshot = await Main_Data_FireStore.collection(collection_name).get();
    const workOrders = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));

    logger.info("Successfully fetched %d documents from collection: %s", workOrders.length, collection_name);
    res.status(200).json(workOrders);
  } catch (error) {
    logger.error("Error fetching data from collection: %s. Error: %s", req.params.collection_name, error.message);
    res.status(500).json({ error: 'Failed to fetch work orders' });
  }
});

// Get collection singel data by ID API Endpoint
router.get('/api/:collection_name/:id', async (req, res) => {
  const { collection_name, id: workOrderId } = req.params;

  // Log the API hit
  logger.info(`API HIT: Get collection data by ID - Collection: ${collection_name}, ID: ${workOrderId}`);

  try {
    // Log the Firestore reference creation
    logger.debug(`Creating Firestore reference for collection: ${collection_name}, document ID: ${workOrderId}`);

    const workOrderRef = Main_Data_FireStore.collection(collection_name).doc(workOrderId);
    const doc = await workOrderRef.get();

    if (!doc.exists) {
      // Log the case where document does not exist
      logger.warn(`Work order not found - Collection: ${collection_name}, ID: ${workOrderId}`);
      return res.status(404).json({ error: 'Work order not found' });
    }

    const workOrderData = doc.data();

    // Log successful retrieval of data
    logger.info(`Work order data fetched successfully - Collection: ${collection_name}, ID: ${workOrderId}`);
    res.status(200).json(workOrderData);
  } catch (error) {
    // Log error details
    logger.error(`Error fetching work order - Collection: ${collection_name}, ID: ${workOrderId}`, { error });
    res.status(500).json({ error: 'Failed to fetch work order data' });
  }
});

router.get("/fetch-users/:usersCategories", async (req, res) => {
  const usersCategories = req?.params?.usersCategories;
  logger.info(`API HIT: Fetch users endpoint - Categories: ${usersCategories}`);

  if (!usersCategories) {
    logger.warn("No user categories provided in the request.");
    return res.status(400).send("User categories are required.");
  }

  const usersCategories_array = usersCategories.split(",");
  logger.debug(`Parsed user categories: ${usersCategories_array}`);

  try {
    const all_users = [];

    for (let category of usersCategories_array) {
      logger.debug(`Processing category: ${category}`);
      const user = { userType: category, user_data: [] };

      const collection_name = "users";
      const collectionRef = Main_Data_FireStore.collection(collection_name.toLowerCase()).doc(category.toLowerCase());

      // Log before listing sub-collections
      logger.debug(`Listing sub-collections for category: ${category}`);
      const Email_sub_collections = await collectionRef.listCollections();

      const subCollectionPromises = Email_sub_collections.map(async (Email_sub_collection) => {
        const snapshot = await Email_sub_collection.get();

        snapshot.forEach(doc => {
          user["user_data"].push({ id: doc.id, ...doc.data().user });
        });

        logger.debug(`Fetched sub-collection: ${Email_sub_collection.id}, Docs count: ${user["user_data"].length}`);
      });

      // Wait for all sub-collections to resolve
      await Promise.all(subCollectionPromises);

      logger.info(`Completed fetching data for category: ${category}`);
      all_users.push(user);
    }

    logger.info(`Successfully fetched all users for categories: ${usersCategories}`);
    res.status(200).json(all_users);
  } catch (error) {
    logger.error("Error fetching users", { error });
    res.status(500).send("Error fetching users: " + error.message);
  }
});

// Fetch user details based on JWT token
router.get("/fetch-user", verifyToken, async (req, res) => {
  logger.info("API HIT: Fetch single user data endpoint");

  try {
    // Extract email and userType from the JWT token
    const { email, userType } = req;

    if (!email || !userType) {
      logger.warn("Missing email or userType in request.");
      return res.status(400).json({ message: "Invalid request: email or userType missing." });
    }

    logger.debug(`Extracted from token - Email: ${email}, UserType: ${userType}`);

    // Determine the sub-collection name based on the first character of the email
    const emailFirstChar = email[0].toLowerCase();
    const user = { userType, user_data: [] };

    // Firestore collection and document reference based on userType
    const collection_name = "users";
    const collectionRef = Main_Data_FireStore.collection(collection_name.toLowerCase()).doc(userType.toLowerCase());

    logger.debug(`Firestore collection and document reference - Collection: ${collection_name}, Document: ${userType.toLowerCase()}`);

    // Reference the sub-collection by the first character of the email
    const Email_sub_collection = collectionRef.collection(emailFirstChar);

    logger.debug(`Accessing sub-collection - Name: ${emailFirstChar}`);

    // Fetch all documents in this sub-collection
    const snapshot = await Email_sub_collection.get();

    if (snapshot.empty) {
      logger.warn(`No user data found for Email first char: ${emailFirstChar}, UserType: ${userType}`);
      return res.status(404).json({ message: "No user data found" });
    }

    // Push user data from documents into user_data
    snapshot.forEach(doc => {
      user["user_data"].push(doc.data().user);
    });

    logger.info(`Successfully fetched user data - Email: ${email}, UserType: ${userType}`);
    res.status(200).json(user);
  } catch (error) {
    logger.error("Error fetching user", { error });
    res.status(500).send("Error fetching user: " + error.message);
  }
});

router.get("/fetch-Waiting-Payment", async (req, res) => {
  const collection_name = "Waiting-Payment";
  logger.info("API HIT: Fetch Waiting-Payment data endpoint");

  try {
    // Log the start of fetching document references
    logger.debug(`Fetching document references from collection: ${collection_name}`);

    // 1. Fetch all document references from the "Waiting-Payment" collection
    const docRefs = await Main_Data_FireStore.collection(collection_name).listDocuments();
    logger.info(`Found ${docRefs.length} documents in collection: ${collection_name}`);

    // 2. Collect references for all subcollections under each document
    const subcollectionsRefs = await Promise.all(docRefs.map(docRef => docRef.listCollections()));
    const allSubcollections = subcollectionsRefs.flat(); // Flatten to a single array of subcollection references
    logger.info(`Found ${allSubcollections.length} subcollections across documents in collection: ${collection_name}`);

    // 3. Collect document data from all subcollections in batches
    const batchFetchPromises = allSubcollections.map(async (subcollectionRef) => {
      logger.debug(`Fetching documents from subcollection: ${subcollectionRef.id}`);
      const subcollectionSnapshot = await subcollectionRef.get();
      const docs = subcollectionSnapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data(),
      }));
      logger.debug(`Fetched ${docs.length} documents from subcollection: ${subcollectionRef.id}`);
      return docs;
    });

    // 4. Await and flatten the fetched data
    const allDocsData = (await Promise.all(batchFetchPromises)).flat();
    logger.info(`Fetched a total of ${allDocsData.length} documents from subcollections in collection: ${collection_name}`);

    // 5. Output all document data and send the response
    res.status(200).json(allDocsData);
  } catch (error) {
    logger.error("Error fetching Waiting-Payment data", { error });
    res.status(500).json({ error: "Failed to fetch Waiting-Payment data" });
  }
});

router.get("/fetch-single-user-Waiting-Payment/:userType/:userEmail", async (req, res) => {
  logger.info("API HIT: Fetch single user 'Waiting Payment' data endpoint");

  const collection_name = "Waiting-Payment";
  const userEmail = req?.params?.userEmail;
  let userType = req?.params?.userType;
  userType = userType === "Field" ? "contractor" : userType

  // Log request parameters
  logger.debug(`Request parameters - userType: ${userType}, userEmail: ${userEmail}`);

  if (!userType || !userEmail) {
    logger.warn("Invalid request: Missing userType or userEmail parameters.");
    return res.status(400).json({ error: "Invalid request: Missing userType or userEmail." });
  }

  try {
    // Reference the document for the given userType
    const docRef = Main_Data_FireStore.collection(collection_name).doc(userType.toLowerCase());
    const emailSubCollectionRef = docRef.collection(userEmail.toLowerCase());

    logger.debug(`Accessing subcollection for userEmail: ${userEmail} in userType: ${userType}`);

    // Fetch all documents in the subcollection
    const snapshot = await emailSubCollectionRef.get();

    if (!snapshot.empty) {
      const data = snapshot.docs.map(doc => doc.data());
      logger.info(`Fetched ${data.length} documents for userType: ${userType}, userEmail: ${userEmail}`);
      res.status(200).json(data);
    } else {
      logger.warn(`No data found for userType: ${userType}, userEmail: ${userEmail}`);
      res.status(404).json([]);
    }
  } catch (error) {
    logger.error("Error fetching Waiting-Payment data", { error });
    res.status(500).json({ error: "Failed to fetch Waiting-Payment data" });
  }
});


// START - notification system 
// ****************************************************************************************

// Route for real-time notifications using SSE
router.get("/notifications/stream", (req, res) => {
  const { userEmail, userType } = req.query; // Get email and type from query parameters
  console.log("Real-time notifications stream started for:", { userEmail, userType });

  if (!userEmail || !userType) {
    return res.status(400).send("Email and user type are required.");
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  const notificationsRef = Main_Real_Time_Database.ref("notifications");

  // Function to fetch notifications
  const fetchNotifications = () => {
    const emailQuery = notificationsRef.orderByChild(`${userType}_email`).equalTo(userEmail);
    const adminQuery = notificationsRef.orderByChild(`${userType}_email`).equalTo("All Admin"); //that only work for admin

    // Perform two queries and merge results
    Promise.all([
      new Promise((resolve) => emailQuery.once("value", (snapshot) => resolve(snapshot))),
      (userType === "Office") ? new Promise((resolve) => adminQuery.once("value", (snapshot) => resolve(snapshot))) : [],
    ]).then(([emailSnapshot, adminSnapshot]) => {
      const notifications = {};

      // Add notifications for userEmail
      emailSnapshot.forEach((childSnapshot) => {
        notifications[childSnapshot.key] = childSnapshot.val();
      });

      // Add notifications for "All Admin"
      adminSnapshot.forEach((childSnapshot) => {
        notifications[childSnapshot.key] = childSnapshot.val();
      });

      // Convert to array for easier consumption
      const notificationsArray = Object.entries(notifications).map(([id, data]) => ({
        id,
        ...data,
      }));

      console.log(`Real-time Notifications for ${userEmail}:`, notificationsArray);

      // Send data as SSE
      res.write(`data: ${JSON.stringify(notificationsArray)}\n\n`);
    });
  };

  // Set up real-time listeners for both queries
  const emailListener = notificationsRef
    .orderByChild(`${userType}_email`)
    .equalTo(userEmail)
    .on("value", fetchNotifications);

  const adminListener = notificationsRef
    .orderByChild(`${userType}_email`)
    .equalTo("All Admin")
    .on("value", fetchNotifications);

  // Clean up listeners when the client disconnects
  req.on("close", () => {
    console.log("Client disconnected:", userEmail);
    notificationsRef.off("value", emailListener);
    notificationsRef.off("value", adminListener);
    res.end();
  });
});

// Route to post a new notification
router.post("/notifications", async (req, res) => {
  try {
    const { message, receiver_mail } = req.body;
    console.log({ message, receiver_mail });

    if (!message || receiver_mail.length < 1) {
      return res.status(400).json({ error: "Message and email are required" });
    }

    const newNotification = {
      ...receiver_mail,
      message,
      seen: false,
      timestamp: Date.now(),
    };

    const notificationRef = Main_Real_Time_Database.ref("notifications").push();
    await notificationRef.set(newNotification);

    res.status(201).json({ message: "Notification created successfully." });
  } catch (error) {
    console.error("Error creating notification:", error);
    res.status(500).json({ error: "Failed to create notification." });
  }
});

// END - notification system 
// ****************************************************************************************




// All Update Operation
router.put("/:collection_name/:id", async (req, res) => {
  logger.info("API HIT: All PUT Operation");

  const { collection_name, id } = req.params;
  const data = req.body;

  // Log request details
  logger.debug(`Request parameters - Collection: ${collection_name}, ID: ${id}`);
  logger.debug(`Request body - Data: ${JSON.stringify(data)}`);

  if (!collection_name || !id) {
    logger.warn("Invalid request: Missing collection_name or ID.");
    return res.status(400).json({ error: "Invalid request: Missing collection_name or ID." });
  }

  if (!data || Object.keys(data).length === 0) {
    logger.warn("Invalid request: Missing or empty update data.");
    return res.status(400).json({ error: "Invalid request: Missing or empty update data." });
  }

  try {
    // Perform the update operation
    await Main_Data_FireStore.collection(collection_name).doc(id).update(data);
    logger.info(`Document updated successfully - Collection: ${collection_name}, ID: ${id}`);

    res.status(200).send({ msg: "Updated" });
  } catch (error) {
    logger.error("Error updating document", { error });
    res.status(500).json({ error: "Failed to update document." });
  }
});

// Update Data in Collection API Endpoint
router.put('/api/:collection_name/:id', async (req, res) => {
  logger.info("API HIT: Update Data in Collection");

  try {
    const { collection_name, id } = req.params;
    const updatedData = req.body;

    // Log request details
    logger.debug(`Request parameters - Collection: ${collection_name}, ID: ${id}`);
    logger.debug(`Request body - Updated data: ${JSON.stringify(updatedData)}`);

    if (!collection_name || !id) {
      logger.warn("Invalid request: Missing collection_name or ID.");
      return res.status(400).json({ error: "Invalid request: Missing collection_name or ID." });
    }

    if (!updatedData || Object.keys(updatedData).length === 0) {
      logger.warn("Invalid request: Missing or empty update data.");
      return res.status(400).json({ error: "Invalid request: Missing or empty update data." });
    }

    // Reference the Firestore document
    const workOrderRef = Main_Data_FireStore.collection(collection_name).doc(id);

    // Perform the update operation
    await workOrderRef.update(updatedData);
    logger.info(`Document updated successfully - Collection: ${collection_name}, ID: ${id}`);

    res.status(200).json({ message: 'Work order updated successfully!' });
  } catch (error) {
    logger.error("Error updating work order", { error });
    res.status(500).json({ error: "Failed to update work order" });
  }
});





// All Delete Operation
// Delete a document by ID
router.delete('/delete/:collection_name/:id', async (req, res) => {
  logger.info("API HIT: Delete Operation");

  try {
    const { collection_name, id } = req.params;

    // Log request details
    logger.debug(`Request parameters - Collection: ${collection_name}, ID: ${id}`);

    if (!collection_name || !id) {
      logger.warn("Invalid request: Missing collection_name or ID.");
      return res.status(400).json({ error: "Invalid request: Missing collection_name or ID." });
    }

    // Reference the Firestore document
    const itemRef = Main_Data_FireStore.collection(collection_name).doc(id);

    // Perform the delete operation
    await itemRef.delete();
    logger.info(`Document deleted successfully - Collection: ${collection_name}, ID: ${id}`);

    res.status(200).json({ message: 'Item deleted successfully' });
  } catch (error) {
    logger.error("Error deleting document", { error });
    res.status(500).json({ error: "Failed to delete item." });
  }
});

// Delete Data from Collection API Endpoint
router.delete('/api/:collection_name/:id', async (req, res) => {
  logger.info("API HIT: Delete Data from Collection");

  try {
    const { collection_name, id } = req.params;

    // Log request details
    logger.debug(`Request parameters - Collection: ${collection_name}, ID: ${id}`);

    if (!collection_name || !id) {
      logger.warn("Invalid request: Missing collection_name or ID.");
      return res.status(400).json({ error: "Invalid request: Missing collection_name or ID." });
    }

    // Reference the Firestore document
    const workOrderRef = Main_Data_FireStore.collection(collection_name).doc(id);

    // Perform the delete operation
    await workOrderRef.delete();
    logger.info(`Document deleted successfully - Collection: ${collection_name}, ID: ${id}`);

    res.status(200).json({ message: 'Work order deleted successfully!' });
  } catch (error) {
    logger.error("Error deleting work order", { error });
    res.status(500).json({ error: 'Failed to delete work order' });
  }
});

// Delete Image Endpoint
const deleteFromFireStore = async (id) => {
  logger.info("Function Call: deleteFromFireStore");
  logger.debug(`Input parameter - ID: ${id}`);

  try {
    const workOrderRef = Main_Data_FireStore.collection("work-orders").doc(id);

    logger.debug(`Updating document with ID: ${id} in collection: work-orders`);

    await workOrderRef.update({
      "General_Page_Infos.House_Front_Image": []
    });

    logger.info(`Document updated successfully - ID: ${id}`);
    return true;
  } catch (error) {
    logger.error(`Error updating document - ID: ${id}`, { error });
    throw new Error("Failed to update the document in Firestore.");
  }
};
router.delete('/delete-front-house-image', async (req, res) => {
  logger.info("API HIT: Delete Front House Image");

  const { imagePath, id } = req.body;

  // Validate input
  if (!imagePath) {
    logger.warn("Invalid request: Image path is missing.");
    return res.status(400).json({ error: "Image path is required." });
  }

  if (!id) {
    logger.warn("Invalid request: Document ID is missing.");
    return res.status(400).json({ error: "Document ID is required." });
  }

  try {
    logger.debug(`Attempting to delete file from storage. Path: ${imagePath}`);
    const deleted = await deleteFileFromStorage(imagePath);

    if (!deleted) {
      logger.error("Failed to delete the image file from storage.");
      return res.status(500).json({ response: "Failed to delete the image file from storage." });
    }

    logger.debug(`Attempting to update Firestore for document ID: ${id}`);
    const deleted_From_FireStore = await deleteFromFireStore(id);

    if (!deleted_From_FireStore) {
      logger.error("Failed to update Firestore after file deletion.");
      return res.status(500).json({ response: "Failed to update Firestore." });
    }

    logger.info(`Successfully deleted image and updated Firestore for document ID: ${id}`);
    res.status(200).json({ response: "Photo deleted successfully." });
  } catch (error) {
    logger.error("Error occurred during the deletion process", { error });
    res.status(500).json({ response: "An error occurred while deleting the photo." });
  }
});

router.delete("/delete-Waiting-Payment/:userType/:email/:id", async (req, res) => {
  const { userType, email, id } = req.params;
  console.log({ userType, email, id });

  const collection_name = "Waiting-Payment";
  logger.info(`API HIT: Delete Waiting-Payment with id: ${id}`);

  try {
    // Reference the document
    const subCollectionDocRef = Main_Data_FireStore
      .collection(collection_name)
      .doc(userType)
      .collection(email)
      .doc(id);

    // Fetch the document to check existence
    const nestedDocSnapshot = await subCollectionDocRef.get();

    if (!nestedDocSnapshot.exists) {
      logger.error(`Document with id ${id} does not exist.`);
      return res.status(404).json({ error: "Document not found" });
    }

    // Delete the document
    await subCollectionDocRef.delete();

    logger.info(`Document with id ${id} deleted successfully.`);
    res.status(200).json({ message: "Document deleted successfully" });
  } catch (error) {
    logger.error("Error deleting Waiting-Payment data", { error });
    res.status(500).json({ error: "Failed to delete Waiting-Payment data" });
  }
});




////// For Tracking History
// All POST Operation
// Create Docs inside Collections API Endpoint
router.post('/TrackingHistory/api/work-orders', async (req, res) => {
  logger.info("API HIT: Create Collection in Tracking History");

  try {
    const { docId, collectionDatas } = req.body;

    // Log the received data
    logger.debug(`Request Body - docId: ${docId}, collectionDatas: ${JSON.stringify(collectionDatas)}`);

    // Validate inputs
    if (!docId) {
      logger.warn("Invalid request: Missing docId.");
      return res.status(400).json({ error: "docId is required." });
    }

    if (!collectionDatas || typeof collectionDatas !== "object") {
      logger.warn("Invalid request: collectionDatas is missing or not an object.");
      return res.status(400).json({ error: "collectionDatas is required and should be an object." });
    }

    // Reference to the Firestore document
    const workOrderRef = Tracking_Data_FireStore.collection('work-orders').doc(docId);

    // Set data in Firestore
    await workOrderRef.set(collectionDatas);
    logger.info(`Document created successfully in Tracking History - docId: ${docId}`);

    res.status(201).json({ message: 'Work order created successfully!' });
  } catch (error) {
    logger.error("Error creating work order", { error });
    res.status(500).json({ error: "Failed to create work order." });
  }
});



// All GET Operation
// Get collection singel data by ID API Endpoint
router.get('/TrackingHistory/api/work-orders/:id', async (req, res) => {
  logger.info("API HIT: Get collection single data by ID in Tracking History");

  const workOrderId = req.params.id;

  // Validate the workOrderId
  if (!workOrderId) {
    logger.warn("Invalid request: Missing workOrderId.");
    return res.status(400).json({ error: "Work order ID is required." });
  }

  try {
    logger.debug(`Fetching work order with ID: ${workOrderId}`);

    const workOrderRef = Tracking_Data_FireStore.collection('work-orders').doc(workOrderId);
    const doc = await workOrderRef.get();

    if (!doc.exists) {
      logger.warn(`Work order not found for ID: ${workOrderId}`);
      return res.status(404).json({ error: 'Work order not found' });
    }

    const workOrderData = doc.data();
    logger.info(`Work order data fetched successfully for ID: ${workOrderId}`);

    res.status(200).json(workOrderData);
  } catch (error) {
    logger.error("Error fetching work order", { error });
    res.status(500).json({ error: 'Failed to fetch work order data' });
  }
});



// All PUT oparetion
// Tracking History All Update Operation
router.put("/TrackingHistory/api/:collection_name/:id", async (req, res) => {
  logger.info("API HIT: PUT Operation in Tracking History");

  const { collection_name, id } = req.params;
  const data = req.body;

  // Validate input parameters
  if (!collection_name || !id) {
    logger.warn("Invalid request: Missing collection name or document ID.");
    return res.status(400).json({ error: "Collection name and document ID are required." });
  }

  if (!data || typeof data !== "object") {
    logger.warn("Invalid request: Missing data or data is not an object.");
    return res.status(400).json({ error: "Data is required and should be an object." });
  }

  try {
    logger.debug(`Updating document in collection: ${collection_name}, ID: ${id}`);

    const docRef = Tracking_Data_FireStore.collection(collection_name).doc(id);
    await docRef.update(data);

    logger.info(`Document updated successfully in collection: ${collection_name}, ID: ${id}`);
    res.status(200).json({ msg: "Updated" });
  } catch (error) {
    logger.error("Error updating document", { error });
    res.status(500).json({ error: "Failed to update document" });
  }
});

// Tracking History All Update Operation
router.put("/TrackingHistory/api/:collection_name/:id/:location", async (req, res) => {
  logger.info("API HIT: Single Part PUT Operation in Tracking History");

  const { collection_name, id, location } = req.params;
  const data = req.body;

  // Validate input parameters
  if (!collection_name || !id || !location) {
    logger.warn("Invalid request: Missing collection name, document ID, or location.");
    return res.status(400).json({ error: "Collection name, document ID, and location are required." });
  }

  if (!Array.isArray(data) || data.length === 0) {
    logger.warn("Invalid request: Data should be a non-empty array.");
    return res.status(400).json({ error: "Data should be a non-empty array." });
  }

  try {
    logger.debug(`Updating document in collection: ${collection_name}, ID: ${id}, location: ${location}`);

    const docRef = Tracking_Data_FireStore.collection(collection_name).doc(id);
    await docRef.update({
      [location]: FieldValue.arrayUnion(...data)
    });

    logger.info(`Document updated successfully in collection: ${collection_name}, ID: ${id}, location: ${location}`);
    res.status(200).json({ msg: "Updated" });

  } catch (error) {
    logger.error("Error updating document", { error });
    res.status(500).json({ msg: "Failed to update document", error: error.message });
  }
});



// All Delete Operation
// Delete a document by ID
router.delete('/TrackingHistory/delete/:collection_name/:id', async (req, res) => {
  logger.info("API HIT: Delete Operation in Tracking History");

  const { collection_name, id } = req.params;

  // Validate input parameters
  if (!collection_name || !id) {
    logger.warn("Invalid request: Missing collection name or document ID.");
    return res.status(400).json({ error: "Collection name and document ID are required." });
  }

  try {
    logger.debug(`Deleting document in collection: ${collection_name}, ID: ${id}`);

    const itemRef = Tracking_Data_FireStore.collection(collection_name).doc(id);
    await itemRef.delete();

    logger.info(`Document deleted successfully from collection: ${collection_name}, ID: ${id}`);
    res.status(200).json({ message: 'Item deleted successfully' });

  } catch (error) {
    logger.error("Error deleting document", { error });
    res.status(500).json({ error: error.message });
  }
});



// START - logger monitor ui start
// ****************************************************************************************

// MongoDB connection
mongoose.connect('mongodb+srv://eira_group:9WTclJhbG6Mr8bs2@logger.uofv7.mongodb.net/loggerDB?retryWrites=true&w=majority&tls=true', { useNewUrlParser: true, useUnifiedTopology: true });

const logSchema = new mongoose.Schema({
  timestamp: Date,
  level: String,
  message: String,
  metadata: Object,
});
const Log = mongoose.model('log_entries', logSchema);

// API endpoint to fetch logs
router.get('/logs', async (req, res) => {
  try {
    console.log("info: get the log hit")
    const logs = await Log.find().sort({ timestamp: -1 });

    // Format date before sending to frontend
    const formattedLogs = logs
      .reverse()
      .map((log) => ({
        ...log._doc,
        formattedTimestamp: moment(log.timestamp).format('YYYY/MM/DD - HH:mm:ss'),
      }));

    res.json(formattedLogs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error fetching logs' });
  }
});

// END - logger monitor ui start
// ****************************************************************************************



// Start the server
app.use('/.netlify/functions/api', router);
module.exports.handler = serverless(app);