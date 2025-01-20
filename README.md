# An Evoting system with M2354 (TrustZone)

## Branch introduction

Only `trustZone` and `trustZone_ble` are the main branch we are using.

- `trustZone` branch is a voting machine communicate with python code (`agents.py`).
- `trustZone_ble` branch is a voting machine communicate with Android APP.

## Preperation

### Environment build up

- visit the link and it will tell you how to set up Keil IDE and how to download the BSP
- Could start with page 28.

https://www.nuvoton.com/export/resource-files/UM_NuMaker-M2354_EN_Rev1.pdf

- This is the link of M2354 BSP, you should download it before you start.

https://github.com/OpenNuvoton/M2354BSP

- These are the files inside the BSP

![image](https://hackmd.io/_uploads/rJlgjhfLyl.png)

## How to Load the code into M2354!! (`trustZone` version)

1. Navigate to the path "\BSP\SampleCode\TrustZone".

2. Clone this project using Git.

3. Copy the `Evoting` library in the project to the path "BSP/Library". 

![image](https://hackmd.io/_uploads/SJE3R2GL1l.png)

4. Launch Keil MDK, open the project within the software, then click on the "batch build" button.

![image](https://hackmd.io/_uploads/B1zw62GLyg.png)


5. Right-click on the "Project: Secure" and choose "Set as Active Project"

6. Click the "Download" button to initiate the flashing process and transfer the secure program onto the board.
![image](https://hackmd.io/_uploads/rkKhahf8ye.png)


7. Right-click on the "Project: Nonsecure" and select "Set as Active Project".

8. Click the "Download" button to start the flashing process and transfer the nonsecure program onto the board.
![image](https://hackmd.io/_uploads/HkUTTnzLyl.png)

9. After pressing the reset button on the board, you'll get a brand new voting machine.

![image](https://hackmd.io/_uploads/rk07A2GIJg.png)

## How to run the voting system (Python version)

### requirements

- please refer to the Ureka requirements.

https://github.com/nthu-logos-lab/ureka-framework/tree/main/requirements

- Please check the port of M2354

![image](https://hackmd.io/_uploads/rJ1Zl6zI1l.png)


- Modify the code here in `agents.py` to make sure your python code can find the serial port of M2354

[code link](https://github.com/nthu-logos-lab/Evoting-M2354/blob/ee788b01c346968d29a3af707ec552df3919fc07/agents.py#L20)

- Then you can run the voting system by executing the `agents.py`.


        python3 agents.py

https://github.com/OpenNuvoton/M2354BSP

- These are the files inside the BSP

![image](https://hackmd.io/_uploads/rJlgjhfLyl.png)
