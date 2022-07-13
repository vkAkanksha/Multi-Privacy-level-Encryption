from flask import *
import encryption,decryption
import os,io
app = Flask(__name__)

@app.route('/')
def hello_world():
    return render_template('index.html')

@app.route('/dec')
def hello_world1():
    return render_template('decrypt.html')

@app.route('/try.html', methods = ['POST','GET'])
def success():  
    if request.method == 'POST':  
        fname = request.files['file'] 
        key=request.form['key']
        fname.save(fname.filename)  
        encryption.encryption(fname.filename,key)
        os.remove(fname.filename)
        return render_template("try.html", name = fname.filename)  

@app.route('/decrypt', methods = ['POST','GET'])
def decrypt():
    if request.method == 'POST':  
        fname = request.form['file'] 
        dkey=request.form['key'] 
        decryption.decryption("enc"+fname,dkey)

        # def download_file(filename):
        file_path = "decenc"+fname
        file_handle = open(file_path, 'r')

        # This *replaces* the `remove_file` + @after_this_request code above
        def stream_and_remove_file():
            yield from file_handle
            file_handle.close()
            os.remove(file_path)

        return current_app.response_class(
            stream_and_remove_file(),
            headers={'Content-Disposition': 'attachment', 'filename': fname, 'Content-Type': 'text/plain'}
            )
            
if __name__=="__main__":
    app.run(debug=True)
