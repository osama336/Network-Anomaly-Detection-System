#run in your terminal/cmd
sudo apt install tshark 
sudo chmod +x /usr/bin/dumpcap
sudo usermod -a -G wireshark "$USER"
#for (debian/ubuntu/mint/kali)

#install anaconda3 by downloading the sh file from https://repo.anaconda.com/archive/Anaconda3-2024.10-1-Linux-x86_64.sh 
then cd (dictory/folder where you download the anaconda file) and run sh (name of the sh file.sh)

#copy paste these in your anaconda terminal or use (source ~/anaconda3/bin/activate) or (source ~/miniconda3/bin/activate) on linux 
cd (the dictory/folder where you put the files) && 
conda env create -f environment.yaml && 
conda activate streamlit &&
pip install -r requirements.txt &&
streamlit run ./NADS.py

#next time you want to run the spyshark.py just
cd (the dictory/folder where you put both files) in your anaconda terminal && 
conda activate streamlit &&
streamlit run ./NADS.py

#you can run "nmcli device status" without qutotation to see what interface you have on your device
