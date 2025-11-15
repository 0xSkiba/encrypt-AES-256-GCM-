const crypto = require('crypto');
const fs = require('fs');
const readline = require('readline');

// ============================================
// ФУНКЦИЯ ШИФРОВАНИЯ/ДЕШИФРОВАНИЯ (AES-256-GCM)
// ============================================

function cryptoSimple(data, password, mode) {
  const algorithm = 'aes-256-gcm';
  const saltLength = 32;
  const ivLength = 12;
  const keyLength = 32;
  const authTagLength = 16;
  const iterations = 600000;

  if (mode === 'encrypt') {
    const salt = crypto.randomBytes(saltLength);
    const key = crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha512');
    const iv = crypto.randomBytes(ivLength);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv, { authTagLength });
    const plaintext = Buffer.from(data, 'utf8');
    let encrypted = cipher.update(plaintext);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    const result = Buffer.concat([salt, iv, authTag, encrypted]);
    return result.toString('base64');
  } 
  else if (mode === 'decrypt') {
    const buffer = Buffer.from(data, 'base64');
    const minLength = saltLength + ivLength + authTagLength + 1;
    
    if (buffer.length < minLength) {
      throw new Error(`Неверный формат данных (минимум ${minLength} байт, получено ${buffer.length})`);
    }
    
    const salt = buffer.subarray(0, saltLength);
    const iv = buffer.subarray(saltLength, saltLength + ivLength);
    const authTag = buffer.subarray(saltLength + ivLength, saltLength + ivLength + authTagLength);
    const encrypted = buffer.subarray(saltLength + ivLength + authTagLength);
    
    const key = crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha512');
    
    try {
      const decipher = crypto.createDecipheriv(algorithm, key, iv, { authTagLength });
      decipher.setAuthTag(authTag);
      let decrypted = decipher.update(encrypted);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      return decrypted.toString('utf8');
    } catch (error) {
      throw new Error('Ошибка аутентификации: неверный пароль или поврежденные данные');
    }
  }
  throw new Error('mode должен быть "encrypt" или "decrypt"');
}

// ============================================
// РАБОТА С ФАЙЛАМИ
// ============================================

function readTextFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  return content.split('\n').map(line => line.trim()).filter(line => line.length > 0);
}

function readCSVFile(filePath, columnIndex = 0) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n').map(line => line.trim()).filter(line => line.length > 0);
  return lines.map(line => {
    const columns = line.split(',').map(col => col.trim());
    return columns[columnIndex] || '';
  }).filter(item => item.length > 0);
}

// ✨ НОВАЯ ФУНКЦИЯ: чтение нескольких столбцов CSV
function readCSVWithMultipleHeaders(filePath, columnNames) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n').map(line => line.trim()).filter(line => line.length > 0);
  
  if (lines.length === 0) throw new Error('Файл пуст');
  
  const headers = lines[0].split(',').map(h => h.trim());
  const columnIndices = columnNames.map(name => {
    const index = headers.indexOf(name);
    if (index === -1) {
      throw new Error(`Столбец "${name}" не найден. Доступные: ${headers.join(', ')}`);
    }
    return index;
  });
  
  const result = {};
  columnNames.forEach(name => {
    result[name] = [];
  });
  
  lines.slice(1).forEach(line => {
    const columns = line.split(',').map(col => col.trim());
    columnNames.forEach((name, idx) => {
      const value = columns[columnIndices[idx]] || '';
      if (value.length > 0) {
        result[name].push(value);
      }
    });
  });
  
  return result;
}

function readCSVWithHeaders(filePath, columnName) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n').map(line => line.trim()).filter(line => line.length > 0);
  
  if (lines.length === 0) throw new Error('Файл пуст');
  
  const headers = lines[0].split(',').map(h => h.trim());
  const columnIndex = headers.indexOf(columnName);
  
  if (columnIndex === -1) {
    throw new Error(`Столбец "${columnName}" не найден. Доступные: ${headers.join(', ')}`);
  }
  
  return lines.slice(1).map(line => {
    const columns = line.split(',').map(col => col.trim());
    return columns[columnIndex] || '';
  }).filter(item => item.length > 0);
}

function readXLSXFile(filePath, columnIndex = 0) {
  try {
    const XLSX = require('xlsx');
    const workbook = XLSX.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    const sheet = workbook.Sheets[sheetName];
    const data = XLSX.utils.sheet_to_json(sheet, { header: 1 });
    return data.map(row => row[columnIndex] || '').filter(item => item && item.toString().trim().length > 0).map(item => item.toString());
  } catch (error) {
    if (error.code === 'MODULE_NOT_FOUND') {
      console.log('\n⚠️  Для работы с XLSX файлами установите библиотеку:');
      console.log('   npm install xlsx\n');
      throw new Error('Библиотека xlsx не установлена');
    }
    throw error;
  }
}

// ✨ НОВАЯ ФУНКЦИЯ: чтение нескольких столбцов XLSX
function readXLSXWithMultipleHeaders(filePath, columnNames) {
  try {
    const XLSX = require('xlsx');
    const workbook = XLSX.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    const sheet = workbook.Sheets[sheetName];
    const data = XLSX.utils.sheet_to_json(sheet);
    
    const result = {};
    columnNames.forEach(name => {
      result[name] = data
        .map(row => row[name] || '')
        .filter(item => item && item.toString().trim().length > 0)
        .map(item => item.toString());
    });
    
    return result;
  } catch (error) {
    if (error.code === 'MODULE_NOT_FOUND') {
      console.log('\n⚠️  Для работы с XLSX файлами установите библиотеку:');
      console.log('   npm install xlsx\n');
      throw new Error('Библиотека xlsx не установлена');
    }
    throw error;
  }
}

function readXLSXWithHeaders(filePath, columnName) {
  try {
    const XLSX = require('xlsx');
    const workbook = XLSX.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    const sheet = workbook.Sheets[sheetName];
    const data = XLSX.utils.sheet_to_json(sheet);
    return data.map(row => row[columnName] || '').filter(item => item && item.toString().trim().length > 0).map(item => item.toString());
  } catch (error) {
    if (error.code === 'MODULE_NOT_FOUND') {
      console.log('\n⚠️  Для работы с XLSX файлами установите библиотеку:');
      console.log('   npm install xlsx\n');
      throw new Error('Библиотека xlsx не установлена');
    }
    throw error;
  }
}

function saveToFile(data, outputPath, format = 'txt') {
  if (format === 'txt') {
    fs.writeFileSync(outputPath, data.join('\n'), 'utf8');
  } else if (format === 'csv') {
    fs.writeFileSync(outputPath, data.join('\n'), 'utf8');
  } else if (format === 'xlsx') {
    try {
      const XLSX = require('xlsx');
      const worksheet = XLSX.utils.aoa_to_sheet(data.map(item => [item]));
      const workbook = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(workbook, worksheet, 'Sheet1');
      XLSX.writeFile(workbook, outputPath);
    } catch (error) {
      if (error.code === 'MODULE_NOT_FOUND') {
        console.log('\n⚠️  Для работы с XLSX файлами установите библиотеку:');
        console.log('   npm install xlsx\n');
        throw new Error('Библиотека xlsx не установлена');
      }
      throw error;
    }
  }
}

// ✨ НОВАЯ ФУНКЦИЯ: сохранение с несколькими столбцами
function saveMultipleColumnsToFile(dataObject, outputPath, format = 'csv') {
  if (format === 'csv') {
    const columnNames = Object.keys(dataObject);
    const maxLength = Math.max(...columnNames.map(name => dataObject[name].length));
    
    let csvContent = columnNames.join(',') + '\n';
    
    for (let i = 0; i < maxLength; i++) {
      const row = columnNames.map(name => dataObject[name][i] || '');
      csvContent += row.join(',') + '\n';
    }
    
    fs.writeFileSync(outputPath, csvContent, 'utf8');
  } else if (format === 'xlsx') {
    try {
      const XLSX = require('xlsx');
      const columnNames = Object.keys(dataObject);
      const maxLength = Math.max(...columnNames.map(name => dataObject[name].length));
      
      const rows = [columnNames];
      for (let i = 0; i < maxLength; i++) {
        const row = columnNames.map(name => dataObject[name][i] || '');
        rows.push(row);
      }
      
      const worksheet = XLSX.utils.aoa_to_sheet(rows);
      const workbook = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(workbook, worksheet, 'Sheet1');
      XLSX.writeFile(workbook, outputPath);
    } catch (error) {
      if (error.code === 'MODULE_NOT_FOUND') {
        console.log('\n⚠️  Для работы с XLSX файлами установите библиотеку:');
        console.log('   npm install xlsx\n');
        throw new Error('Библиотека xlsx не установлена');
      }
      throw error;
    }
  }
}

// ============================================
// ИНТЕРАКТИВНОЕ МЕНЮ
// ============================================

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function question(query) {
  return new Promise(resolve => rl.question(query, resolve));
}

async function main() {
  try {
    console.clear();
    console.log('═══════════════════════════════════════════════════════════');
    console.log('   🔐 AES-256-GCM Шифрование/Дешифрование');
    console.log('═══════════════════════════════════════════════════════════\n');

    console.log('📋 Выберите режим работы:');
    console.log('  1 - Шифрование (encrypt)');
    console.log('  2 - Дешифрование (decrypt)\n');
    
    const modeChoice = await question('Ваш выбор (1 или 2): ');
    const mode = modeChoice.trim() === '1' ? 'encrypt' : 'decrypt';
    
    console.log(`\n✅ Режим: ${mode === 'encrypt' ? 'Шифрование' : 'Дешифрование'}\n`);

    const password = await question('🔑 Введите пароль: ');
    
    if (!password || password.trim().length === 0) {
      console.log('\n❌ Пароль не может быть пустым!');
      return;
    }
    
    console.log('✅ Пароль принят\n');

    console.log('📂 Выберите источник данных:');
    console.log('  1 - Ручной ввод (одна строка)');
    console.log('  2 - Из файла без заголовков (txt/csv/xlsx)');
    console.log('  3 - Из файла с одним заголовком (csv/xlsx)');
    console.log('  4 - Из файла с несколькими заголовками (csv/xlsx) ✨ НОВОЕ\n');
    
    const sourceChoice = await question('Ваш выбор (1, 2, 3 или 4): ');
    console.log(`\nВы выбрали: ${sourceChoice}\n`);

    if (sourceChoice.trim() === '1') {
      console.log('📝 Введите данные для обработки:');
      const data = await question('> ');
      
      if (!data || data.trim().length === 0) {
        console.log('\n❌ Данные не могут быть пустыми!');
        return;
      }

      console.log('\n⏳ Обработка...\n');
      const result = cryptoSimple(data, password, mode);
      
      console.log('═══════════════════════════════════════════════════════════');
      console.log('✅ РЕЗУЛЬТАТ:');
      console.log('═══════════════════════════════════════════════════════════');
      console.log(result);
      console.log('═══════════════════════════════════════════════════════════\n');

    } else if (sourceChoice.trim() === '2') {
      console.log('📂 Введите путь к файлу (txt/csv/xlsx):');
      const inputPath = await question('> ');
      
      if (!fs.existsSync(inputPath)) {
        console.log('\n❌ Файл не найден!');
        return;
      }

      console.log('\n⏳ Чтение файла...');
      let dataArray = [];
      
      if (inputPath.endsWith('.xlsx')) {
        dataArray = readXLSXFile(inputPath, 0);
      } else if (inputPath.endsWith('.csv')) {
        dataArray = readCSVFile(inputPath, 0);
      } else {
        dataArray = readTextFile(inputPath);
      }

      console.log(`✅ Прочитано строк: ${dataArray.length}`);
      console.log('\n⏳ Обработка данных...');

      const results = [];
      for (let i = 0; i < dataArray.length; i++) {
        try {
          const result = cryptoSimple(dataArray[i], password, mode);
          results.push(result);
          if ((i + 1) % 100 === 0) {
            console.log(`   Обработано: ${i + 1}/${dataArray.length}`);
          }
        } catch (error) {
          console.log(`⚠️  Ошибка на строке ${i + 1}: ${error.message}`);
          results.push(`ERROR: ${error.message}`);
        }
      }

      console.log(`✅ Обработано: ${dataArray.length}/${dataArray.length}\n`);

      const ext = inputPath.split('.').pop();
      const outputPath = inputPath.replace(`.${ext}`, `_${mode}.${ext}`);
      
      console.log(`💾 Сохранение в: ${outputPath}`);
      saveToFile(results, outputPath, ext === 'xlsx' ? 'xlsx' : 'txt');
      console.log('✅ Готово!\n');

    } else if (sourceChoice.trim() === '3') {
      console.log('📂 Введите путь к файлу (csv/xlsx):');
      const inputPath = await question('> ');
      
      if (!fs.existsSync(inputPath)) {
        console.log('\n❌ Файл не найден!');
        return;
      }

      if (!inputPath.endsWith('.csv') && !inputPath.endsWith('.xlsx')) {
        console.log('\n❌ Поддерживаются только CSV и XLSX файлы!');
        return;
      }

      console.log('📋 Введите название столбца для обработки:');
      const columnName = await question('> ');

      console.log('\n⏳ Чтение файла...');
      let dataArray = [];
      
      if (inputPath.endsWith('.xlsx')) {
        dataArray = readXLSXWithHeaders(inputPath, columnName);
      } else {
        dataArray = readCSVWithHeaders(inputPath, columnName);
      }

      console.log(`✅ Прочитано строк: ${dataArray.length}`);
      console.log('\n⏳ Обработка данных...');

      const results = [];
      for (let i = 0; i < dataArray.length; i++) {
        try {
          const result = cryptoSimple(dataArray[i], password, mode);
          results.push(result);
          if ((i + 1) % 100 === 0) {
            console.log(`   Обработано: ${i + 1}/${dataArray.length}`);
          }
        } catch (error) {
          console.log(`⚠️  Ошибка на строке ${i + 1}: ${error.message}`);
          results.push(`ERROR: ${error.message}`);
        }
      }

      console.log(`✅ Обработано: ${dataArray.length}/${dataArray.length}\n`);

      const ext = inputPath.split('.').pop();
      const outputPath = inputPath.replace(`.${ext}`, `_${mode}.${ext}`);
      
      console.log(`💾 Сохранение в: ${outputPath}`);
      saveToFile(results, outputPath, ext === 'xlsx' ? 'xlsx' : 'csv');
      console.log('✅ Готово!\n');

    } else if (sourceChoice.trim() === '4') {
      // ✨ НОВЫЙ РЕЖИМ: несколько столбцов
      console.log('📂 Введите путь к файлу (csv/xlsx):');
      const inputPath = await question('> ');
      
      if (!fs.existsSync(inputPath)) {
        console.log('\n❌ Файл не найден!');
        return;
      }

      if (!inputPath.endsWith('.csv') && !inputPath.endsWith('.xlsx')) {
        console.log('\n❌ Поддерживаются только CSV и XLSX файлы!');
        return;
      }

      console.log('📋 Введите названия столбцов через запятую (например: email,password,token):');
      const columnNamesInput = await question('> ');
      const columnNames = columnNamesInput.split(',').map(name => name.trim()).filter(name => name.length > 0);

      if (columnNames.length === 0) {
        console.log('\n❌ Необходимо указать хотя бы один столбец!');
        return;
      }

      console.log(`\n✅ Будут обработаны столбцы: ${columnNames.join(', ')}\n`);
      console.log('⏳ Чтение файла...');
      
      let dataObject = {};
      
      try {
        if (inputPath.endsWith('.xlsx')) {
          dataObject = readXLSXWithMultipleHeaders(inputPath, columnNames);
        } else {
          dataObject = readCSVWithMultipleHeaders(inputPath, columnNames);
        }
      } catch (error) {
        console.log(`\n❌ ${error.message}`);
        return;
      }

      console.log('✅ Файл прочитан');
      console.log('\n⏳ Обработка данных...\n');

      const resultsObject = {};
      let totalProcessed = 0;

      for (const columnName of columnNames) {
        const dataArray = dataObject[columnName];
        console.log(`📊 Обработка столбца "${columnName}" (${dataArray.length} строк)...`);
        
        resultsObject[columnName] = [];
        
        for (let i = 0; i < dataArray.length; i++) {
          try {
            const result = cryptoSimple(dataArray[i], password, mode);
            resultsObject[columnName].push(result);
            totalProcessed++;
          } catch (error) {
            console.log(`⚠️  Ошибка в столбце "${columnName}", строка ${i + 1}: ${error.message}`);
            resultsObject[columnName].push(`ERROR: ${error.message}`);
          }
        }
        
        console.log(`✅ Столбец "${columnName}" обработан\n`);
      }

      console.log(`✅ Всего обработано: ${totalProcessed} значений\n`);

      const ext = inputPath.split('.').pop();
      const outputPath = inputPath.replace(`.${ext}`, `_${mode}.${ext}`);
      
      console.log(`💾 Сохранение в: ${outputPath}`);
      saveMultipleColumnsToFile(resultsObject, outputPath, ext === 'xlsx' ? 'xlsx' : 'csv');
      console.log('✅ Готово!\n');

    } else {
      console.log('\n❌ Неверный выбор! Пожалуйста, выберите 1, 2, 3 или 4.');
    }

  } catch (error) {
    console.log(`\n❌ Ошибка: ${error.message}\n`);
  } finally {
    rl.close();
  }
}

main().catch(error => {
  console.error('Критическая ошибка:', error);
  rl.close();
});
