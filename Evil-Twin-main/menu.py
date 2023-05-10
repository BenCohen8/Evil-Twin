import attack
import defence

if __name__ == '__main__':
    input1 = 0;
    while int(input1) != 1 and int(input1) != 0:
        input1 = input("Press 1 for attack and 2 for defence");

    if int(input1)==1:
        attack.attack()
    else:
        defence.defence()
