import functions
from config import UI


def show_main_menu():
    print(f"{UI.B_BLUE}{UI.BOLD}\n{'=' * 40}\n  {'LOG ORGANIZER syslog/apache'.center(30)}\n{'=' * 40}\n{UI.RESET}")
    user_path = input(r"Enter the path for log file: ")

    while True:
        print(f"\n{UI.B_BLUE}{UI.BOLD}{'=' * 40}\n  {'MAIN MENU'.center(30)}\n{'=' * 40}{UI.RESET}")
        print(f'\n{UI.BOLD}1. Log file analysis'
              f'\n2. Save the analysis to a CSV file'
              f'\n0. Exit{UI.RESET}')

        choice = input('\nSelect an option from the menu: ')

        match choice:

            case '1':
                datetime_changed = functions.change_datetime_apache(logs_path=user_path)
                org_logs = functions.organize_it(datetime_changed)
                functions.output(org_logs)

            case '2':
                datetime_changed = functions.change_datetime_apache(logs_path=user_path)
                tuple_events = functions.organize_it(datetime_changed)
                (eventos, ip_dic, *_) = tuple_events
                functions.update_eventos(eventos, ip_dic)
                functions.export_csv(eventos)

            case '0':
                print(f'{UI.B_MAGENTA}{UI.BOLD}GOODBYE{UI.RESET}')
                break


def main():
    show_main_menu()

if __name__ == '__main__':
    main()