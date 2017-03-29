package com.zhaoyuzhang.winemateinternaltool;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareUltralight;
import android.nfc.tech.Ndef;
import android.nfc.tech.NdefFormatable;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.text.Html;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.zhaoyuzhang.winemateinternaltool.thriftfiles.TagInfo;
import com.zhaoyuzhang.winemateinternaltool.thriftfiles.UploadTagInfoResponse;
import com.zhaoyuzhang.winemateinternaltool.thriftfiles.WineMateServices;

import org.apache.thrift.TException;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import static android.nfc.tech.MifareUltralight.PAGE_SIZE;
import static com.zhaoyuzhang.winemateinternaltool.Configs.RANDOM_KEY_RANGE;
import static com.zhaoyuzhang.winemateinternaltool.Configs.TAG_PASSWORD_BYTES;
import static com.zhaoyuzhang.winemateinternaltool.thriftfiles.UploadTagInfoStatus.UPLOAD_DUPLICATE_TAG_ID;
import static com.zhaoyuzhang.winemateinternaltool.thriftfiles.UploadTagInfoStatus.UPLOAD_SUCCESS;

/*
 * Ref [1] NTAG213/215/216 NFC Forum Type 2 Tag compliant IC with 144/504/888 bytes user memory
 *         http://www.nxp.com/documents/data_sheet/NTAG213_215_216.pdf
 */

// NTAG216 default values:
// [page 0] 04 59 5C 89 //serial number (3 bytes +  check byte 0)
// [page 1] 22 12 4A 80 //serial number (4 bytes)
// [page 2] FA 48 00 00 //check byte 1(1 byte), internal(1 byte), lock bytes(2 bytes)
// [page 3] E1 10 6D 00 //Capability Container(CC), 6D --> 872 bytes (NDEF memory size)
// [page 4] 03 00 FE 00 //user memory
// [page 5 -
//  ...
//  page 225] 00 00 00 00
// [page 226] 00 00 00 BD // dynamic lock bytes(3 bytes), RFUI (1 byte)
// [page 227] 04 00 00 FF // CFG 0
// [page 228] 00 05 00 00 // CFG 1
// [page 229] 00 00 00 00 // PWD
// [page 230] 00 00 00 00 // PACK(2 bytes), RFUI (1 byte)
public class MainActivity extends AppCompatActivity {

    NfcAdapter mNfcAdapter;
    TextView mEventLog;
    TextView mWineIDConfirmed;
    TextView mRollNumberConfirmed;
    TextView mOperatorIDConfirmed;
    TextView mNotificationCounterConfirmed;
    EditText mWineID;
    EditText mRollNumber;
    EditText mOperatorID;
    EditText mNotificationCounter;
    Button mDoneButton;
    Button mResetButton;
    Button mClearButton;

    final String WINEMATE_TAG_TYPE = "tagtalk/winemate";
    final String WINEMATE_TAG_NDEF_MESSAGE = "WineMateTag";
    final String WINEMATE_PACKAGE_NAME = "co.tagtalk.winemate";

    final byte[] PACK = {(byte)0x12, (byte)0x34, (byte)0x00, (byte)0x00};

    final int PAGE_OFFSET_STATIC_LOCK_213 = 2;
    final int PAGE_OFFSET_AUTHENTICATION_CODE_213 = 26;
    final int PAGE_OFFSET_PWD_213 = 43;
    final int PAGE_OFFSET_PACK_213 = 44;
    final int PAGE_OFFSET_DYNAMIC_LOCK_213 = 40;
    final int PAGE_OFFSET_CFG0_213 = 41;
    final int PAGE_OFFSET_CFG1_213 = 42;

    final int PAGE_OFFSET_STATIC_LOCK_215 = 2;
    final int PAGE_OFFSET_AUTHENTICATION_CODE_215 = 26;
    final int PAGE_OFFSET_PWD_215 = 133;
    final int PAGE_OFFSET_PACK_215 = 134;
    final int PAGE_OFFSET_DYNAMIC_LOCK_215 = 130;
    final int PAGE_OFFSET_CFG0_215 = 131;
    final int PAGE_OFFSET_CFG1_215 = 132;

    final int PAGE_OFFSET_STATIC_LOCK_216 = 2;
    final int PAGE_OFFSET_AUTHENTICATION_CODE_216 = 26;
    final int PAGE_OFFSET_PWD_216 = 229;
    final int PAGE_OFFSET_PACK_216 = 230;
    final int PAGE_OFFSET_DYNAMIC_LOCK_216 = 226;
    final int PAGE_OFFSET_CFG0_216 = 227;
    final int PAGE_OFFSET_CFG1_216 = 228;

    final int AUTHENTICATION_CODE_LENGTH = 32; // 32 bytes

    // Enable static lock for pages 03h ~ 0Fh. [OTP]
    final byte[] CMD_ENABLE_STATIC_LOCK = {(byte)0x00, (byte)0x00, (byte)0xFF, (byte)0xFF};
    // Enable dynamic lock for pages 10h ~ end. [OTP]
    final byte[] CMD_ENABLE_DYNAMIC_LOCK = {(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x00};
    // Enable password protection for pages 1Ah ~ END
    final byte[] CMD_SET_PW_PROTECTION_STARTING_PAGE = {(byte)0x04, (byte)0x00, (byte)0x00, (byte)0x1A};
    // Enable password protection for read and write access
    final byte[] CMD_SET_PW_PROTECTION_ACCESS = {(byte)0x80, (byte)0x05, (byte)0x00, (byte)0x00};

    public static final String EVENT_PREFIX = "<font color=#424242>[EVENT] ";
    public static final String SUCCESS_PREFIX = "<font color=#388E3C>[SUCCESS] ";
    public static final String FAILED_PREFIX = "<font color=#B71C1C>[FAILED] ";

    private boolean readyToWrite = false;
    private byte[] tagPassword;
    private byte[] authenticationCodeByte;
    private TagInfo tagInfo;
    private String tagType;
    private String tagID;
    private MifareUltralight ultralight;
    private Tag tag;
    private int notificationCounterThreshold = 10;
    private int counter = 0;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
        mWineID = (EditText) findViewById(R.id.wine_id_input);
        mRollNumber = (EditText) findViewById(R.id.roll_number_input);
        mOperatorID = (EditText) findViewById(R.id.operator_id_input);
        mNotificationCounter = (EditText) findViewById(R.id.notification_counter_input);
        mDoneButton = (Button) findViewById(R.id.done_button);
        mResetButton = (Button) findViewById(R.id.reset_button);
        mClearButton = (Button) findViewById(R.id.clear_button);
        mEventLog = (TextView) findViewById(R.id.event_log);
        mWineIDConfirmed = (TextView)findViewById(R.id.wine_id_confirmed);
        mRollNumberConfirmed = (TextView)findViewById(R.id.roll_number_confirmed);
        mOperatorIDConfirmed = (TextView)findViewById(R.id.operator_id_confirmed);
        mNotificationCounterConfirmed = (TextView)findViewById(R.id.notification_counter_confirmed);

        tagInfo = new TagInfo();
        mEventLog.setMovementMethod(new ScrollingMovementMethod());

        //tagInfo.tagID = "048AEA0A6E4D81";
        mWineIDConfirmed.setVisibility(View.INVISIBLE);
        mRollNumberConfirmed.setVisibility(View.INVISIBLE);
        mOperatorIDConfirmed.setVisibility(View.INVISIBLE);
        mNotificationCounterConfirmed.setVisibility(View.INVISIBLE);

        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);

        mDoneButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                if (mWineID != null && mWineID.getText().toString().length() == 0) {
                    mWineID.setVisibility(View.VISIBLE);
                    mWineIDConfirmed.setVisibility(View.INVISIBLE);
                    Toast.makeText(MainActivity.this, "Please enter a valid wine ID!", Toast.LENGTH_SHORT).show();
                    return;
                }

                if (mRollNumber != null && mRollNumber.getText().toString().length() == 0) {
                    mRollNumber.setVisibility(View.VISIBLE);
                    mRollNumberConfirmed.setVisibility(View.INVISIBLE);
                    Toast.makeText(MainActivity.this, "Please enter a valid roll number!", Toast.LENGTH_SHORT).show();
                    return;
                }

                if (mOperatorID != null && mOperatorID.getText().toString().length() == 0) {
                    mOperatorID.setVisibility(View.VISIBLE);
                    mOperatorIDConfirmed.setVisibility(View.INVISIBLE);
                    Toast.makeText(MainActivity.this, "Please enter a valid operatorId!", Toast.LENGTH_SHORT).show();
                    return;
                }

                if (mWineID != null && mRollNumber!= null && mOperatorID != null) {
                    tagInfo.wineID = Integer.parseInt(mWineID.getText().toString());
                    tagInfo.rollNumber = Integer.parseInt(mRollNumber.getText().toString());
                    tagInfo.operatorID = mOperatorID.getText().toString();

                    readyToWrite = true;

                    String wineIdConfirmed = "Wine ID is set to:    " + mWineID.getText().toString();
                    mWineID.setVisibility(View.INVISIBLE);
                    mWineIDConfirmed.setVisibility(View.VISIBLE);
                    mWineIDConfirmed.setText(wineIdConfirmed);

                    String rollNumberConfirmed = "Roll number is set to:    " + mRollNumber.getText().toString();
                    mRollNumber.setVisibility(View.INVISIBLE);
                    mRollNumberConfirmed.setVisibility(View.VISIBLE);
                    mRollNumberConfirmed.setText(rollNumberConfirmed);

                    String operatorIDConfirmed = "Operator ID is set to:    " + mOperatorID.getText().toString();
                    mOperatorID.setVisibility(View.INVISIBLE);
                    mOperatorIDConfirmed.setVisibility(View.VISIBLE);
                    mOperatorIDConfirmed.setText(operatorIDConfirmed);

                    if (mNotificationCounter != null && mNotificationCounter.getText().toString().length() > 0) {
                        String notificationCounterConfirmed = "Counter is set to:    " + mNotificationCounter.getText().toString();
                        notificationCounterThreshold = Integer.parseInt(mNotificationCounter.getText().toString());
                        mNotificationCounter.setVisibility(View.INVISIBLE);
                        mNotificationCounterConfirmed.setVisibility(View.VISIBLE);
                        mNotificationCounterConfirmed.setText(notificationCounterConfirmed);
                    } else {
                        String notificationCounterConfirmed = "Counter is not set!";
                        if (mNotificationCounter != null) {
                            mNotificationCounter.setVisibility(View.INVISIBLE);
                        }
                        mNotificationCounterConfirmed.setVisibility(View.VISIBLE);
                        mNotificationCounterConfirmed.setText(notificationCounterConfirmed);
                    }

                    mEventLog.append(Html.fromHtml(EVENT_PREFIX + "Ready to write tags..."));
                    mEventLog.append("\n");
                }

            }
        });

        mResetButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                readyToWrite = false;

                if (mWineID != null) {
                    mWineID.setVisibility(View.VISIBLE);
                    mWineID.setText("");
                }

                mWineIDConfirmed.setVisibility(View.INVISIBLE);

                if (mRollNumber != null) {
                    mRollNumber.setVisibility(View.VISIBLE);
                    mRollNumber.setText("");
                }

                mRollNumberConfirmed.setVisibility(View.INVISIBLE);

                if (mOperatorID != null) {
                    mOperatorID.setVisibility(View.VISIBLE);
                    mOperatorID.setText("");
                }

                mOperatorIDConfirmed.setVisibility(View.INVISIBLE);

                if (mNotificationCounter != null) {
                    mNotificationCounter.setVisibility(View.VISIBLE);
                    mNotificationCounter.setText("");
                }

                mNotificationCounterConfirmed.setVisibility(View.INVISIBLE);

                counter = 0;

                Toast.makeText(MainActivity.this, "Reset!", Toast.LENGTH_SHORT).show();
            }
        });

        mClearButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                mEventLog.setText("");
            }
        });
    }

    protected void onResume() {
        super.onResume();
        Log.v("### ", "onResume");
        enableForegroundDispatchSystem();
    }

    @Override
    protected void onPause() {
        super.onPause();
        mNfcAdapter.disableForegroundDispatch(this);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Log.v("### ", "onNewIntent");

        if (readyToWrite) {
            boolean isWritable = false;

            if (intent.hasExtra(NfcAdapter.EXTRA_TAG)) {

                // Here is the workflow to create a WineMate NFC tag with password protection
                tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                ultralight = MifareUltralight.get(tag);

                tagID = byteArrayToHexString(tag.getId());
                tagInfo.tagID = tagID;
                Log.v("### tagID", tagID);

                tagType = getTagType(ultralight);
                Log.v("### tagType", tagType);

                mEventLog.append(Html.fromHtml(EVENT_PREFIX + "Find " + "[" + tagType + "] " + tagID));
                mEventLog.append("\n");

                Ndef ndef = Ndef.get(tag);
                if (ndef != null && ndef.isWritable()) {
                    isWritable = true;
                }

                if (!isWritable) {
                    mEventLog.append(Html.fromHtml(FAILED_PREFIX + tagID + " is not writable! Validating tag..."));
                    mEventLog.append("\n");

                    // Validate TagInfo
                    final ValidateTagTask validateTagTask = new ValidateTagTask(MainActivity.this);
                    validateTagTask.execute(tagID);
                } else {

                    // Generate a random authentication code (32 bytes)
                    String authenticationCodeString;
                    authenticationCodeByte = generateAuthenticationCode("SHA-256");
                    authenticationCodeString = byteArrayToHexString(authenticationCodeByte);
                    tagInfo.authenticationKey = authenticationCodeString;

                    // Generate a random tag password (4 bytes)
                    tagPassword = generateTagPassword(TAG_PASSWORD_BYTES);
                    tagInfo.tagPassword = (byteArrayToHexString(tagPassword));

                    // Write TagInfo to Database;
                    final UploadTagInfoTask uploadTagInfoTask = new UploadTagInfoTask(MainActivity.this, mEventLog);
                    uploadTagInfoTask.execute(tagInfo);
                }
            }
        }
    }

    public class UploadTagInfoTask extends AsyncTask<TagInfo, Void, UploadTagInfoResponse> {

        private Activity activity;
        private TextView mTextView;

        public UploadTagInfoTask(Activity activity, TextView result) {
            this.activity = activity;
            this.mTextView = result;
        }

        @Override
        protected UploadTagInfoResponse doInBackground(TagInfo... params) {
            TTransport transport = new TSocket(Configs.SERVER_ADDRESS, Configs.PORT_NUMBER);
            UploadTagInfoResponse uploadTagInfoResponse = new UploadTagInfoResponse();

            try{

                transport.open();

                TProtocol protocol = new TBinaryProtocol(transport);
                WineMateServices.Client client = new WineMateServices.Client(protocol);

                uploadTagInfoResponse = client.uploadTagInfo(params[0]);


            } catch (TException x) {
                x.printStackTrace();
            }
            transport.close();

            return uploadTagInfoResponse;
        }

        @Override
        protected void onPostExecute(UploadTagInfoResponse uploadTagInfoResponse) {

            if (uploadTagInfoResponse.status == UPLOAD_SUCCESS) {
                mTextView.append(Html.fromHtml(SUCCESS_PREFIX + "Tag info is successfully uploaded!"));
                mTextView.append("\n");
                writeFlow(tagType);

            } else if (uploadTagInfoResponse.status == UPLOAD_DUPLICATE_TAG_ID) {
                mTextView.append(Html.fromHtml(FAILED_PREFIX + "Tag info already exists in database! Trying to write tag again!"));
                mTextView.append("\n");

                //Retrieve authenticationCodeByte and tagPassword from database;
                if (uploadTagInfoResponse.tagInfo != null) {
                    authenticationCodeByte = hexStringToByteArray(uploadTagInfoResponse.tagInfo.getAuthenticationKey());
                    tagPassword = hexStringToByteArray(uploadTagInfoResponse.tagInfo.getTagPassword());
                    tagInfo.authenticationKey = uploadTagInfoResponse.tagInfo.getAuthenticationKey();
                    tagInfo.tagPassword = uploadTagInfoResponse.tagInfo.getTagPassword();

                    writeFlow(tagType);
                } else {
                    mTextView.append(Html.fromHtml(FAILED_PREFIX + "No record found in database. Manual check is needed!"));
                    mTextView.append("\n\n");
                }
            }else {
                mTextView.append(Html.fromHtml(FAILED_PREFIX + "Tag info is failed to uploaded!"));
                mTextView.append("\n\n");
            }

            if (counter == notificationCounterThreshold) {
                mTextView.append(Html.fromHtml(EVENT_PREFIX + counter + " tags are written!"));
                mTextView.append("\n\n");
                counter = 0;
            }
        }
    }


    public class ValidateTagTask extends AsyncTask<String, Void, TagInfo> {

        private Activity activity;

        public ValidateTagTask(Activity activity) {
            this.activity = activity;
        }

        @Override
        protected TagInfo doInBackground(String... params) {
            TTransport transport = new TSocket(Configs.SERVER_ADDRESS, Configs.PORT_NUMBER);
            TagInfo tagRecord = new TagInfo();

            try{

                transport.open();

                TProtocol protocol = new TBinaryProtocol(transport);
                WineMateServices.Client client = new WineMateServices.Client(protocol);

                tagRecord = client.getTagInfo(params[0]);


            } catch (TException x) {
                x.printStackTrace();
            }
            transport.close();

            return tagRecord;
        }

        @Override
        protected void onPostExecute(TagInfo tagRecord) {

            Log.v("ZZZ", "tagRecord:" +  tagRecord);

            if (tagRecord == null) {
                mEventLog.append(Html.fromHtml(FAILED_PREFIX + tagID + "No record is found. Please discard this tag!"));
                mEventLog.append("\n\n");
            } else {

                if (tagRecord.tagPassword == null) {
                    mEventLog.append(Html.fromHtml(FAILED_PREFIX + tagID + "Tag password is not found. Please check internet connection."));
                    mEventLog.append("\n\n");
                    return;
                }

                byte[] password = hexStringToByteArray(tagRecord.getTagPassword());
                String code = "";

                for (int i = 0; i < (AUTHENTICATION_CODE_LENGTH / PAGE_SIZE / 4); i++) {
                    code += (readTag(ultralight, PAGE_OFFSET_AUTHENTICATION_CODE_213 + PAGE_SIZE * i, true, password));
                }

                if (code.equals(tagRecord.getAuthenticationKey())) {
                    mEventLog.append(Html.fromHtml(SUCCESS_PREFIX + tagID + "This is a valid tag!"));
                    mEventLog.append("\n\n");
                } else {
                    mEventLog.append(Html.fromHtml(FAILED_PREFIX + tagID + "No record is found. Please discard this tag!"));
                    mEventLog.append("\n\n");
                }
            }
        }
    }

    private String getTagType(MifareUltralight ultralight) {
        byte[] CMD_GET_VERSION = {0x60};
        int BYTE_NO_VENDOR_ID = 1;
        int BYTE_NO_PRODUCT_TYPE = 2;
        int BYTE_NO_STORAGE_SIZE = 6;
        final byte NXP_VENDOR_ID = 0x04;
        final byte NTAG_TYPE = 0x04;
        final byte NTAG_213_SIZE = 0x0F;
        final byte NTAG_215_SIZE = 0x11;
        final byte NTAG_216_SIZE = 0x13;

        String tagType = null;

        try {
            ultralight.connect();
            byte[] versionInByte = ultralight.transceive(CMD_GET_VERSION);
            if (versionInByte != null && versionInByte[BYTE_NO_VENDOR_ID] == NXP_VENDOR_ID && versionInByte[BYTE_NO_PRODUCT_TYPE] == NTAG_TYPE) {
                switch (versionInByte[BYTE_NO_STORAGE_SIZE]) {
                    case NTAG_213_SIZE:
                        tagType = "NTAG213";
                        break;
                    case NTAG_215_SIZE:
                        tagType = "NTAG215";
                        break;
                    case NTAG_216_SIZE:
                        tagType = "NTAG216";
                        break;
                }
            }
            return tagType;
        } catch (IOException e) {
            Log.v("### Error ", "get tagType");
            return null;
        } finally {
            if (ultralight != null) {
                try {
                    ultralight.close();
                }
                catch (IOException e) {
                    Log.e("### error", "Error closing tag...", e);
                }
            }
        }
    }

    private byte[] generateAuthenticationCode(String hashAlgorithm) {

        byte[] code;
        Random random = new Random();
        String  randomKey = String.valueOf(random.nextInt(RANDOM_KEY_RANGE));

        try {
            MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
            md.update(randomKey.getBytes());
            code = md.digest();
            return code;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    private byte[] generateTagPassword (int bytes) {
        byte[] password = new byte[bytes];

        for (int i = 0; i < bytes; i++) {
            Random randomTagPassword = new Random();
            Integer randomInt = randomTagPassword.nextInt(255);
            password[i] = randomInt.byteValue();
        }

        return password;
    }

    private void authenticate(MifareUltralight ultralight , byte[] password) {
        try {
            byte[] PWD_AUTH_CMD = new byte[password.length + 1];

            //PWD_AUTH code 1Bh [Ref.1 p46]
            PWD_AUTH_CMD[0] = 0x1B;

            int i = 1;
            for (byte b: password) {
                PWD_AUTH_CMD[i] = b;
                i++;
            }
            ultralight.transceive(PWD_AUTH_CMD);
        } catch (IOException e) {
            Log.e("### error", "IOException while authenticating tag...", e);
        }
    }

    private void enableForegroundDispatchSystem(){

        Intent intent = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_RECEIVER_REPLACE_PENDING);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent, 0);

        IntentFilter[] intentFilters = new IntentFilter[]{};

        mNfcAdapter.enableForegroundDispatch(this, pendingIntent, intentFilters, null);
    }

    private String readTag(MifareUltralight ultralight, int offset, boolean isProtected, byte[] password) {
        try {
            ultralight.connect();

            if (isProtected) {
                authenticate(ultralight, password);
            }

            byte[] payloads = ultralight.readPages(offset);
            return byteArrayToHexString(payloads);

        } catch (IOException e) {
            Log.e("### error", "IOException while writing MifareUltralight message...", e);
            return null;
        } finally {
            if (ultralight != null) {
                try {
                    ultralight.close();
                }
                catch (IOException e) {
                    Log.e("### error", "Error closing tag...", e);
                }
            }
        }
    }

    public void writeTag(MifareUltralight ultralight, int offset, byte[] data, boolean isProtected) {
        try {
            ultralight.connect();

            if (isProtected) {
                authenticate(ultralight, tagPassword);
            }

            ultralight.writePage(offset, data);

        } catch (IOException e) {
            Log.e("### error", "IOException while writing MifareUltralight...", e);
        } finally {
            try {
                ultralight.close();
            } catch (IOException e) {
                Log.e("### error", "IOException while closing MifareUltralight...", e);
            }
        }
    }

    private String byteArrayToHexString(byte[] inputArray) {
        int i, j, in;
        String[] hex = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"};
        String hexString = "";

        if (inputArray == null) {
            return hexString;
        }

        for (j = 0; j < inputArray.length; ++j) {
            in = (int) inputArray[j] & 0xff;
            i = (in >> 4) & 0x0f;
            hexString += hex[i];
            i = in & 0x0f;
            hexString += hex[i];
        }
        return hexString;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    // Write NDEF message to Tag.

    private void formatTag(Tag tag, NdefMessage ndefMessage) {
        try {
            NdefFormatable ndefFormatable = NdefFormatable.get(tag);

            if (ndefFormatable == null) {
                Toast.makeText(this, "Tag is not ndef formatable", Toast.LENGTH_SHORT).show();
            } else {
                ndefFormatable.connect();
                ndefFormatable.format(ndefMessage);
                ndefFormatable.close();
            }

        } catch (Exception e) {
            Log.e("formatTag", e.getMessage());
        }
    }

    private boolean writeNdefMessage(Tag tag, NdefMessage ndefMessage) {
        try {

            if (tag == null) {
                Toast.makeText(this, "Tag object cannot be null", Toast.LENGTH_SHORT).show();
                return false;
            }

            Ndef ndef = Ndef.get(tag);

            if (ndef == null) {
                // format tag with the ndef format and writes the message
                formatTag(tag, ndefMessage);
            } else {
                ndef.connect();

                if (!ndef.isWritable()) {
                    Toast.makeText(this, "Tag is not writable!", Toast.LENGTH_SHORT).show();
                    ndef.close();
                    return false;
                }

                ndef.writeNdefMessage(ndefMessage);
                ndef.close();

                Toast.makeText(this, "Tag written!", Toast.LENGTH_SHORT).show();
            }
            return true;

        } catch (Exception e) {
            //Log.e("writeNdefMessage", e.getMessage());
            return false;
        }
    }

    private NdefRecord createTextRecord(String content) {
        try {
            byte[] language = {};

            final byte[] text = content.getBytes("UTF-8");
            final int languageSize = language.length;
            final int textLength = text.length;
            final ByteArrayOutputStream payload = new ByteArrayOutputStream(1 + languageSize + textLength);

            payload.write((byte)(languageSize & 0x1F));
            payload.write(language, 0, languageSize);
            payload.write(text, 0, textLength);

            return new NdefRecord(NdefRecord.TNF_MIME_MEDIA, WINEMATE_TAG_TYPE.getBytes(), new byte[0], payload.toByteArray());

        }catch (UnsupportedEncodingException e) {
            Log.e("createTextRecord", e.getMessage());
        }

        return null;
    }

    private NdefMessage createNdefMessage(String content) {

        NdefRecord ndefRecord = createTextRecord(content);
        return  new NdefMessage(new NdefRecord[]{ndefRecord, NdefRecord.createApplicationRecord(WINEMATE_PACKAGE_NAME)});
    }

    private String readNDEFDataFromNFCTag(NdefMessage ndefMessage) {
        NdefRecord[] ndefRecords = ndefMessage.getRecords();
        String tagContent = null;

        if (ndefRecords != null && ndefRecords.length > 0) {

            NdefRecord ndefRecord = ndefRecords[0];
            byte[] payload = ndefRecord.getPayload();
            tagContent = new String(payload);
        } else {
            Log.v("### read NDEF error", "No NDEF records found");
        }

        return tagContent;
    }

    private void writeFlow(String tagType) {
        // Step 1. Write NDEF message "tagtalk/winemate: WineMateTag" to tag
        // This will use pages from 04h to 0Ch
        NdefMessage ndefMessage = createNdefMessage(WINEMATE_TAG_NDEF_MESSAGE);
        if (!writeNdefMessage(tag, ndefMessage)) {
            mEventLog.append(Html.fromHtml(FAILED_PREFIX + tagID + " is not writable!"));
            mEventLog.append("\n\n");
            return;
        }

        // 4 bytes per page
        int authenticationCodePages = authenticationCodeByte.length / PAGE_SIZE + ((authenticationCodeByte.length % PAGE_SIZE == 0) ? 0 : 1);


        if (tagType != null) {
            switch (tagType) {
                case "NTAG213":
                    // Step 2. Statically lock pages from 03h to 0Fh
                    // [CAUTION] OTP bytes!
                    writeTag(ultralight, PAGE_OFFSET_STATIC_LOCK_213, CMD_ENABLE_STATIC_LOCK, false);

                    // Step 3. Write Authentication code to pages starting from 1Ah

                    for (int i = 0; i < authenticationCodePages; i++) {
                        writeTag(ultralight, PAGE_OFFSET_AUTHENTICATION_CODE_213 + i, Arrays.copyOfRange(authenticationCodeByte, i * 4, i * 4 + 4), false);
                    }

                    // Step 4. Write password for Tag protection to PWD page. 43/133/229 for NTAG 213/215/216
                    writeTag(ultralight, PAGE_OFFSET_PWD_213, tagPassword, false);

                    // Step 5. Write PACK for Tag protection to PACK page. 44/134/230 for NTAG 213/215/216
                    writeTag(ultralight, PAGE_OFFSET_PACK_213, PACK, false);

                    // Step 6. Enable Password Protection for pages from 10h to the end for both read and write access
                    writeTag(ultralight, PAGE_OFFSET_CFG1_213, CMD_SET_PW_PROTECTION_ACCESS, false);
                    writeTag(ultralight, PAGE_OFFSET_CFG0_213, CMD_SET_PW_PROTECTION_STARTING_PAGE, false);

                    // Step 7. Dynamically lock pages from 10h to the end
                    writeTag(ultralight, PAGE_OFFSET_DYNAMIC_LOCK_213, CMD_ENABLE_DYNAMIC_LOCK, true);
                    break;// case NTAG213

                case "NTAG215":
                    // Step 2. Statically lock pages from 03h to 0Fh
                    // [CAUTION] OTP bytes!
                    writeTag(ultralight, PAGE_OFFSET_STATIC_LOCK_215, CMD_ENABLE_STATIC_LOCK, false);

                    // Step 3. Write Authentication code to pages starting from 1Ah

                    for (int i = 0; i < authenticationCodePages; i++) {
                        writeTag(ultralight, PAGE_OFFSET_AUTHENTICATION_CODE_215 + i, Arrays.copyOfRange(authenticationCodeByte, i * 4, i * 4 + 4), false);
                    }

                    // Step 4. Write password for Tag protection to PWD page. 43/133/229 for NTAG 213/215/216
                    writeTag(ultralight, PAGE_OFFSET_PWD_215, tagPassword, false);

                    // Step 5. Write PACK for Tag protection to PACK page. 44/134/230 for NTAG 213/215/216
                    writeTag(ultralight, PAGE_OFFSET_PACK_215, PACK, false);

                    // Step 6. Enable Password Protection for pages from 10h to the end for both read and write access
                    writeTag(ultralight, PAGE_OFFSET_CFG1_215, CMD_SET_PW_PROTECTION_ACCESS, false);
                    writeTag(ultralight, PAGE_OFFSET_CFG0_215, CMD_SET_PW_PROTECTION_STARTING_PAGE, false);

                    // Step 7. Dynamically lock pages from 10h to the end
                    writeTag(ultralight, PAGE_OFFSET_DYNAMIC_LOCK_215, CMD_ENABLE_DYNAMIC_LOCK, true);
                    break;// case NTAG215

                case "NTAG216":
                    // Step 2. Statically lock pages from 03h to 0Fh
                    // [CAUTION] OTP bytes!
                    writeTag(ultralight, PAGE_OFFSET_STATIC_LOCK_216, CMD_ENABLE_STATIC_LOCK, false);

                    // Step 3. Write Authentication code to pages starting from 1Ah

                    for (int i = 0; i < authenticationCodePages; i++) {
                        writeTag(ultralight, PAGE_OFFSET_AUTHENTICATION_CODE_216 + i, Arrays.copyOfRange(authenticationCodeByte, i * 4, i * 4 + 4), false);
                    }

                    // Step 4. Write password for Tag protection to PWD page. 43/133/229 for NTAG 213/215/216
                    writeTag(ultralight, PAGE_OFFSET_PWD_216, tagPassword, false);

                    // Step 5. Write PACK for Tag protection to PACK page. 44/134/230 for NTAG 213/215/216
                    writeTag(ultralight, PAGE_OFFSET_PACK_216, PACK, false);

                    // Step 6. Enable Password Protection for pages from 10h to the end for both read and write access
                    writeTag(ultralight, PAGE_OFFSET_CFG1_216, CMD_SET_PW_PROTECTION_ACCESS, false);
                    writeTag(ultralight, PAGE_OFFSET_CFG0_216, CMD_SET_PW_PROTECTION_STARTING_PAGE, false);

                    // Step 7. Dynamically lock pages from 10h to the end
                    writeTag(ultralight, PAGE_OFFSET_DYNAMIC_LOCK_216, CMD_ENABLE_DYNAMIC_LOCK, true);
                    break; // case NTAG216
            }

            mEventLog.append(Html.fromHtml(SUCCESS_PREFIX + tagID + " is written!"));
            mEventLog.append("\n\n");

            counter ++;
        }
    }

}
