const admin = require('firebase-admin');
const Main_Data_Credentials = require('../../secret_files/Main_Data_Credentials_Key.json');
const Tracking_Data_Credentials = require('../../secret_files/Tracking_Data_Credentials.json');

// Initialize Firebase Admin SDK for Main Data with a unique app name
const Main_Data_Admin = admin.initializeApp({
  credential: admin.credential.cert(Main_Data_Credentials),
  databaseURL: 'https://eira-erp.firebaseio.com',
  storageBucket: 'gs://eira-erp.appspot.com'
}, 'MainDataApp');

const Main_Data_Admin_for_RealTime_DB = admin.initializeApp({
  credential: admin.credential.cert(Main_Data_Credentials),
  databaseURL: 'https://eira-erp-default-rtdb.asia-southeast1.firebasedatabase.app/'
}, 'MainDataAppForRealTimeDB');

const Main_Real_Time_Database = Main_Data_Admin_for_RealTime_DB.database(); // Access Realtime Database 
const Main_Data_FireStore = Main_Data_Admin.firestore(); // Access Firestore 
const bucket = Main_Data_Admin.storage().bucket(); // Access Firebase Storage

// Initialize Firebase Admin SDK for Tracking Data with another unique app name
const Tracking_Data_Admin = admin.initializeApp({
  credential: admin.credential.cert(Tracking_Data_Credentials),
  databaseURL: 'https://eira-tracker.firebaseio.com'
}, 'TrackingDataApp');

const Tracking_Data_FireStore = Tracking_Data_Admin.firestore(); // Access Firestore 

// Export the Firestore database instances
module.exports = {
  Main_Data_Admin,
  Main_Real_Time_Database,
  Main_Data_FireStore,
  Tracking_Data_FireStore,
  bucket
};
