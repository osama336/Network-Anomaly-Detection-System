#run in your terminal/cmd
sudo apt install python3-venv
sudo apt install tshark 
sudo chmod +x /usr/bin/dumpcap
sudo usermod -a -G wireshark "$USER"
#for (debian (or any based distribution)/ubuntu/mint/kali/)

#copy paste these in your terminal on linux 
cd (the dictory/folder where you put the files) &&
python -m venv streamlit && 
source streamlit/bin/activate &&
pip install -r requirements.txt &&
streamlit run ./NADS.py

#next time you want to run the spyshark.py just
cd (the dictory/folder where you put both files) in terminal && 
cd myproject &&
source streamlit/bin/activate &&
streamlit run ./NADS.py

#you can run "nmcli device status" without qutotation to see what interface you have on your device
