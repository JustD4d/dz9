import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
import os

def main():
    """
    Основная функция для анализа данных событий информационной безопасности
    """
    print("=" * 60)
    print("Анализ событий информационной безопасности")
    print("=" * 60)
    
    # Шаг 1: Загрузка данных
    print("\n1. Загрузка данных из файла events.json...")
    
    if not os.path.exists('events.json'):
        print("❌ Ошибка: Файл events.json не найден!")
        print("Создайте файл events.json с данными в формате JSON")
        return
    
    try:
        # Загрузка данных в DataFrame
        df = pd.read_json('events.json')
        print(f"✅ Данные успешно загружены!")
        print(f"   Записей загружено: {len(df)}")
    except Exception as e:
        print(f"❌ Ошибка при загрузке файла: {e}")
        return
    
    # Шаг 2: Просмотр структуры данных
    print("\n2. Структура данных:")
    print("-" * 40)
    print(df.info())
    
    print("\nПервые 5 записей:")
    print(df.head())
    
    # Шаг 3: Анализ распределения по типам событий
    print("\n3. Анализ распределения событий по типам (signature):")
    print("-" * 40)
    
    # Подсчет событий каждого типа
    event_counts = df['signature'].value_counts()
    
    print("\nКоличество событий каждого типа:")
    for event_type, count in event_counts.items():
        print(f"  • {event_type}: {count} событий")
    
    print(f"\nВсего уникальных типов событий: {len(event_counts)}")
    
    # Шаг 4: Дополнительный анализ
    print("\n4. Дополнительный анализ:")
    print("-" * 40)
    
    # Анализ по уровню серьезности
    severity_counts = df['severity'].value_counts()
    print("\nРаспределение по уровню серьезности:")
    print(severity_counts)
    
    # Топ IP-адресов источников
    print("\nТоп-3 IP-адресов источников атак:")
    top_sources = df['source_ip'].value_counts().head(3)
    print(top_sources)
    
    # Шаг 5: Визуализация данных
    print("\n5. Создание визуализаций...")
    
    # Настройка стиля графиков
    sns.set_style("whitegrid")
    plt.figure(figsize=(14, 10))
    
    # График 1: Распределение типов событий
    plt.subplot(2, 2, 1)
    colors = sns.color_palette("husl", len(event_counts))
    bars = plt.bar(event_counts.index, event_counts.values, color=colors)
    plt.title('Распределение событий ИБ по типам', fontsize=14, fontweight='bold')
    plt.xlabel('Тип события', fontsize=12)
    plt.ylabel('Количество событий', fontsize=12)
    plt.xticks(rotation=45, ha='right')
    
    # Добавление значений на столбцы
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                f'{int(height)}', ha='center', va='bottom')
    
    # График 2: Распределение по уровню серьезности (круговая диаграмма)
    plt.subplot(2, 2, 2)
    severity_labels = severity_counts.index
    severity_values = severity_counts.values
    severity_colors = ['#FF6B6B', '#FFD166', '#06D6A0', '#118AB2']  # Цвета для Critical, High, Medium, Low
    
    plt.pie(severity_values, labels=severity_labels, autopct='%1.1f%%', 
            colors=severity_colors[:len(severity_labels)], startangle=90)
    plt.title('Распределение по уровню серьезности', fontsize=14, fontweight='bold')
    
    # График 3: Топ источников атак
    plt.subplot(2, 2, 3)
    top_sources = df['source_ip'].value_counts().head(5)
    sns.barplot(x=top_sources.values, y=top_sources.index, palette="rocket")
    plt.title('Топ-5 IP-адресов источников атак', fontsize=14, fontweight='bold')
    plt.xlabel('Количество событий', fontsize=12)
    plt.ylabel('IP-адрес источника', fontsize=12)
    
    # График 4: Временная шкала событий (если timestamp в правильном формате)
    plt.subplot(2, 2, 4)
    
    # Конвертируем timestamp в datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Группируем по часам
    df['hour'] = df['timestamp'].dt.hour
    hourly_counts = df['hour'].value_counts().sort_index()
    
    plt.plot(hourly_counts.index, hourly_counts.values, marker='o', linewidth=2, color='#7209B7')
    plt.fill_between(hourly_counts.index, hourly_counts.values, alpha=0.3, color='#7209B7')
    plt.title('Активность событий по часам', fontsize=14, fontweight='bold')
    plt.xlabel('Час дня', fontsize=12)
    plt.ylabel('Количество событий', fontsize=12)
    plt.xticks(range(0, 24, 2))
    plt.grid(True, alpha=0.3)
    
    # Настройка общего вида
    plt.tight_layout()
    
    # Сохранение графиков
    plt.savefig('security_analysis_visualization.png', dpi=300, bbox_inches='tight')
    print("✅ Графики сохранены в файл: security_analysis_visualization.png")
    
    # Показать графики
    plt.show()
    
    # Шаг 6: Сохранение результатов анализа в файл
    print("\n6. Сохранение результатов анализа...")
    
    with open('analysis_report.txt', 'w', encoding='utf-8') as report_file:
        report_file.write("=" * 60 + "\n")
        report_file.write("ОТЧЕТ ПО АНАЛИЗУ СОБЫТИЙ ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ\n")
        report_file.write("=" * 60 + "\n\n")
        
        report_file.write("1. ОБЩАЯ СТАТИСТИКА:\n")
        report_file.write(f"   • Всего событий: {len(df)}\n")
        report_file.write(f"   • Уникальных типов событий: {len(event_counts)}\n")
        report_file.write(f"   • Период анализа: {df['timestamp'].min()} - {df['timestamp'].max()}\n\n")
        
        report_file.write("2. РАСПРЕДЕЛЕНИЕ ПО ТИПАМ СОБЫТИЙ:\n")
        for event_type, count in event_counts.items():
            percentage = (count / len(df)) * 100
            report_file.write(f"   • {event_type}: {count} событий ({percentage:.1f}%)\n")
        
        report_file.write("\n3. РАСПРЕДЕЛЕНИЕ ПО УРОВНЮ СЕРЬЕЗНОСТИ:\n")
        for severity, count in severity_counts.items():
            percentage = (count / len(df)) * 100
            report_file.write(f"   • {severity}: {count} событий ({percentage:.1f}%)\n")
    
    print("✅ Отчет сохранен в файл: analysis_report.txt")
    
    print("\n" + "=" * 60)
    print("Анализ завершен успешно! ✓")
    print("=" * 60)

if __name__ == "__main__":
    main()
